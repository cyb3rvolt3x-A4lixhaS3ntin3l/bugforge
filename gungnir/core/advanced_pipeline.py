"""
Advanced pipeline execution engine.

Builds on the basic pipeline loader in ``gungnir.core.pipelines`` and adds:

1. Stage input/output mapping — stages declare named outputs and consume
   named outputs produced by earlier stages.
2. A safe conditional expression engine — no ``eval()``/``exec()``; a small
   tokenizer + recursive-descent parser evaluates expressions against the
   collected named outputs.
3. Per-tool configuration — each stage carries a ``config`` (alias of
   ``options``) dict that is passed to the tool runner.
4. Pipeline validation — ``validate_pipeline`` returns a list of errors.
5. Dry run — ``dry_run_pipeline`` renders a human-readable execution plan,
   evaluating conditions against an empty state.
6. Pipeline variables — ``{{variable}}`` substitution in stage configs, with
   variables defined at the pipeline level (and ``{{target}}`` always
   available).

Expression grammar (precedence low -> high)::

    or_expr      := and_expr ( ('AND'|'OR') and_expr )*
    not_expr     := 'NOT' not_expr | comparison
    comparison   := primary ( ('=='|'!='|'>'|'>='|'<'|'<=') primary )?
    primary      := NUMBER | STRING | 'true' | 'false'
                    | IDENT ( '.' IDENT [ '(' args ')' ] )*
                    | '(' or_expr ')'
    arg          := IDENT '->' or_expr      # lambda
                    | primary
                    | or_expr

Supported examples::

    tech contains 'wordpress' AND live_hosts.count > 0
    endpoints.any(e -> e.contains('/api/'))
    findings.count == 0
    graphql_detected == true
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Union

import yaml

from ..utils.logger import get_logger
from .pipelines import PipelineDef, PipelineStage

log = get_logger()


# ---------------------------------------------------------------------------
# Extra tool names that are not in the orchestrator TOOL_REGISTRY (native /
# built-in Gungnir tools referenced by shipped pipelines). ``validate_pipeline``
# accepts these in addition to anything registered. Callers may extend this set
# or pass ``extra_tools`` to ``validate_pipeline``.
# ---------------------------------------------------------------------------
EXTRA_TOOL_NAMES: Set[str] = {
    "api-discoverer",
    "js-analyzer",
    "param-miner",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AdvancedPipelineStage(PipelineStage):
    """A pipeline stage with named input/output mapping and per-tool config.

    Extends :class:`PipelineStage` (so it is usable anywhere a basic stage is
    expected) with:

    - ``input``:  name (or list of names) of named outputs from previous stages
                  to feed into this stage's tools.
    - ``output``: a named output spec produced by this stage. May be a string
                  (the output name), a dict ``{name: ..., extract: <field>}``,
                  or a list mixing both. ``extract`` aggregates a single field
                  across all result dicts into a flat list (handy for things
                  like ``tech`` from httpx results).
    - ``config``: per-tool options dict, merged on top of ``options``.
    """
    input: Union[str, List[str], None] = None
    output: Union[str, Dict[str, Any], List[Any], None] = None
    config: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class AdvancedPipelineDef(PipelineDef):
    """A pipeline definition with pipeline-level variables."""
    variables: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of running an advanced pipeline."""
    outputs: Dict[str, Any] = field(default_factory=dict)
    stages_executed: List[str] = field(default_factory=list)
    stages_skipped: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    skipped_reasons: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Expression evaluator
# ---------------------------------------------------------------------------

class ExpressionError(Exception):
    """Raised when an expression cannot be parsed or (in strict mode) evaluated."""


# Sentinel for unresolved identifiers (used in non-strict / dry-run mode).
class _Undefined:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:  # noqa: D401
        return False

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<undefined>"


UNDEFINED = _Undefined()


# -- AST nodes ---------------------------------------------------------------

@dataclass
class Num:
    value: Union[int, float]


@dataclass
class Str:
    value: str


@dataclass
class Bool:
    value: bool


@dataclass
class Ident:
    name: str


@dataclass
class Attr:
    """Attribute / property access: ``obj.name`` (e.g. ``foo.count``)."""
    obj: Any
    name: str


@dataclass
class MethodCall:
    """Method call: ``obj.name(args)`` (e.g. ``tech.contains('x')``)."""
    obj: Any
    name: str
    args: List[Any]


@dataclass
class Lambda:
    param: str
    body: Any


@dataclass
class BinOp:
    op: str
    left: Any
    right: Any


@dataclass
class UnaryOp:
    op: str
    operand: Any


# -- Tokenizer ---------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<WS>\s+)
  | (?P<STRING>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")
  | (?P<NUMBER>\d+\.\d+|\d+)
  | (?P<ARROW>->)
  | (?P<OP>==|!=|>=|<=|>|<)
  | (?P<LPAREN>\()
  | (?P<RPAREN>\))
  | (?P<COMMA>,)
  | (?P<DOT>\.)
  | (?P<IDENT>[A-Za-z_][A-Za-z0-9_-]*)
    """,
    re.VERBOSE,
)


def _tokenize(expr: str) -> List[tuple]:
    """Return a list of ``(type, value, pos)`` tuples."""
    tokens: List[tuple] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise ExpressionError(
                f"Unexpected character {expr[pos]!r} at position {pos} in: {expr!r}"
            )
        kind = m.lastgroup
        value = m.group()
        pos = m.end()
        if kind == "WS":
            continue
        if kind == "STRING":
            # strip quotes and unescape
            inner = value[1:-1]
            inner = inner.encode("utf-8").decode("unicode_escape")
            tokens.append(("STRING", inner, m.start()))
        elif kind == "NUMBER":
            num = float(value) if "." in value else int(value)
            tokens.append(("NUMBER", num, m.start()))
        else:
            tokens.append((kind, value, m.start()))
    tokens.append(("EOF", None, len(expr)))
    return tokens


# -- Parser ------------------------------------------------------------------

_KEYWORDS = {"and", "or", "not", "true", "false", "contains", "matches"}


class _Parser:
    def __init__(self, tokens: List[tuple]):
        self.tokens = tokens
        self.i = 0

    # -- helpers --
    def _peek(self) -> tuple:
        return self.tokens[self.i]

    def _next(self) -> tuple:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def _expect(self, kind: str) -> tuple:
        tok = self._next()
        if tok[0] != kind:
            raise ExpressionError(
                f"Expected {kind} but got {tok[0]} ({tok[1]!r}) at position {tok[2]}"
            )
        return tok

    # -- grammar --
    def parse(self):
        node = self.parse_or()
        if self._peek()[0] != "EOF":
            tok = self._peek()
            raise ExpressionError(
                f"Unexpected token {tok[0]} ({tok[1]!r}) at position {tok[2]}"
            )
        return node

    def parse_or(self):
        left = self.parse_and()
        while self._peek()[0] == "IDENT" and self._peek()[1].lower() == "or":
            self._next()
            right = self.parse_and()
            left = BinOp("or", left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self._peek()[0] == "IDENT" and self._peek()[1].lower() == "and":
            self._next()
            right = self.parse_not()
            left = BinOp("and", left, right)
        return left

    def parse_not(self):
        if self._peek()[0] == "IDENT" and self._peek()[1].lower() == "not":
            self._next()
            return UnaryOp("not", self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_primary()
        tok = self._peek()
        if tok[0] == "OP":
            self._next()
            right = self.parse_primary()
            return BinOp(tok[1], left, right)
        if tok[0] == "IDENT" and tok[1].lower() in ("contains", "matches"):
            op = tok[1].lower()
            self._next()
            right = self.parse_primary()
            return BinOp(op, left, right)
        return left

    def parse_primary(self):
        tok = self._peek()
        kind, value, _pos = tok

        if kind == "LPAREN":
            self._next()
            node = self.parse_or()
            self._expect("RPAREN")
            return node

        if kind == "NUMBER":
            self._next()
            return Num(value)

        if kind == "STRING":
            self._next()
            return Str(value)

        if kind == "IDENT":
            # boolean literals
            if value.lower() == "true":
                self._next()
                return Bool(True)
            if value.lower() == "false":
                self._next()
                return Bool(False)
            if value.lower() in ("and", "or", "not", "contains", "matches"):
                raise ExpressionError(
                    f"Unexpected keyword {value!r} at position {_pos}"
                )

            # lambda: IDENT '->' expr
            if (self.tokens[self.i + 1][0] == "ARROW"):
                param = value
                self._next()  # ident
                self._next()  # arrow
                body = self.parse_or()
                return Lambda(param, body)

            self._next()
            node: Any = Ident(value)
            # dotted accesses / method calls
            while self._peek()[0] == "DOT":
                self._next()  # dot
                member_tok = self._expect("IDENT")
                mname = member_tok[1]
                # Logical / boolean keywords are never valid as member names, but
                # contains/matches/any/all/count ARE valid method/property names.
                if mname.lower() in ("and", "or", "not", "true", "false"):
                    raise ExpressionError(
                        f"Reserved word {mname!r} cannot be used as a member "
                        f"name at position {member_tok[2]}"
                    )
                if self._peek()[0] == "LPAREN":
                    args = self.parse_args()
                    node = MethodCall(node, mname, args)
                else:
                    node = Attr(node, mname)
            return node

        raise ExpressionError(
            f"Unexpected token {kind} ({value!r}) at position {_pos}"
        )

    def parse_args(self) -> List[Any]:
        self._expect("LPAREN")
        args: List[Any] = []
        if self._peek()[0] != "RPAREN":
            args.append(self.parse_arg())
            while self._peek()[0] == "COMMA":
                self._next()
                args.append(self.parse_arg())
        self._expect("RPAREN")
        return args

    def parse_arg(self):
        # lambda: IDENT '->' ...
        if (self._peek()[0] == "IDENT"
                and self.tokens[self.i + 1][0] == "ARROW"
                and self._peek()[1].lower() not in _KEYWORDS):
            param = self._peek()[1]
            self._next()  # ident
            self._next()  # arrow
            body = self.parse_or()
            return Lambda(param, body)
        return self.parse_primary()


def parse_expression(expr: str):
    """Tokenize + parse an expression, returning its AST. Raises ExpressionError."""
    tokens = _tokenize(expr)
    return _Parser(tokens).parse()


# -- Evaluator ---------------------------------------------------------------

def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _contains(left: Any, right: Any) -> bool:
    if left is UNDEFINED:
        return False
    if isinstance(left, (list, tuple, set)):
        return right in left
    if isinstance(left, str):
        return str(right) in left
    if isinstance(left, dict):
        return right in left
    return False


def _matches(left: Any, right: Any) -> bool:
    if left is UNDEFINED or not isinstance(left, str):
        return False
    try:
        return re.search(str(right), left) is not None
    except re.error:
        return False


class ExpressionEvaluator:
    """Safely evaluates pipeline condition expressions against named outputs.

    Parameters
    ----------
    context:
        Mapping of named-output name -> value (list / dict / scalar).
    strict:
        When True (default False), referencing an undefined name raises
        :class:`ExpressionError`. When False, undefined names resolve to
        :data:`UNDEFINED` and comparisons return False — useful for dry runs.
    """

    def __init__(self, context: Optional[Dict[str, Any]] = None, strict: bool = False):
        self.context: Dict[str, Any] = dict(context or {})
        self.strict = strict

    # public API -----------------------------------------------------------
    def eval(self, expr: str) -> Any:
        """Parse and evaluate ``expr`` against this evaluator's context."""
        ast = parse_expression(expr)
        return self.eval_ast(ast, dict(self.context))

    def eval_ast(self, node: Any, ctx: Dict[str, Any]) -> Any:
        handler = _NODE_HANDLERS.get(type(node))
        if handler is None:
            raise ExpressionError(f"Unknown AST node: {node!r}")
        return handler(self, node, ctx)

    # node handlers --------------------------------------------------------
    def _num(self, node: Num, ctx):  # noqa: D401
        return node.value

    def _str(self, node: Str, ctx):
        return node.value

    def _bool(self, node: Bool, ctx):
        return node.value

    def _ident(self, node: Ident, ctx):
        if node.name in ctx:
            return ctx[node.name]
        if self.strict:
            raise ExpressionError(f"Undefined variable: {node.name!r}")
        return UNDEFINED

    def _attr(self, node: Attr, ctx):
        obj = self.eval_ast(node.obj, ctx)
        name = node.name
        if name == "count":
            if isinstance(obj, (list, str, dict, tuple, set)):
                return len(obj)
            if obj is UNDEFINED:
                return 0 if not self.strict else UNDEFINED
            # scalar: count doesn't make sense
            if self.strict:
                raise ExpressionError(f".count applied to non-collection: {obj!r}")
            return 0
        if isinstance(obj, dict):
            return obj.get(name, UNDEFINED)
        if obj is UNDEFINED:
            return UNDEFINED
        if self.strict:
            raise ExpressionError(f"Cannot access .{name} on {obj!r}")
        return UNDEFINED

    def _method(self, node: MethodCall, ctx):
        obj = self.eval_ast(node.obj, ctx)
        name = node.name
        if name == "contains":
            arg = self.eval_ast(node.args[0], ctx)
            return _contains(obj, arg)
        if name == "matches":
            arg = self.eval_ast(node.args[0], ctx)
            return _matches(obj, arg)
        if name == "any":
            return self._quantifier(node, ctx, obj, all_=False)
        if name == "all":
            return self._quantifier(node, ctx, obj, all_=True)
        if self.strict:
            raise ExpressionError(f"Unknown method: {name!r}")
        return UNDEFINED

    def _quantifier(self, node: MethodCall, ctx, obj, all_: bool):
        if not isinstance(obj, (list, tuple, set)):
            return False if not all_ else True  # any([])=False, all([])=True-ish
        if not node.args:
            return False
        lam = node.args[0]
        if not isinstance(lam, Lambda):
            # non-lambda predicate arg: treat as truthy check?
            return False
        child = dict(ctx)
        for item in obj:
            child[lam.param] = item
            result = self.eval_ast(lam.body, child)
            truthy = bool(result)
            if all_ and not truthy:
                return False
            if not all_ and truthy:
                return True
        return bool(all_)

    def _lambda(self, node: Lambda, ctx):
        # Lambdas are evaluated lazily by quantifiers; returning the node lets
        # a method treat it as a callable. Not directly callable from expr.
        return node

    def _binop(self, node: BinOp, ctx):
        op = node.op
        if op == "and":
            left = self.eval_ast(node.left, ctx)
            if not left:
                return False
            return bool(self.eval_ast(node.right, ctx))
        if op == "or":
            left = self.eval_ast(node.left, ctx)
            if left:
                return True
            return bool(self.eval_ast(node.right, ctx))
        # comparisons
        left = self.eval_ast(node.left, ctx)
        right = self.eval_ast(node.right, ctx)
        if op == "contains":
            return _contains(left, right)
        if op == "matches":
            return _matches(left, right)
        if left is UNDEFINED or right is UNDEFINED:
            return False
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op in (">", ">=", "<", "<="):
            if not (_is_num(left) and _is_num(right)):
                # also allow str comparison
                if isinstance(left, str) and isinstance(right, str):
                    pass
                else:
                    return False
            if op == ">":
                return left > right
            if op == ">=":
                return left >= right
            if op == "<":
                return left < right
            if op == "<=":
                return left <= right
        raise ExpressionError(f"Unknown operator: {op!r}")

    def _unary(self, node: UnaryOp, ctx):
        if node.op == "not":
            return not bool(self.eval_ast(node.operand, ctx))
        raise ExpressionError(f"Unknown unary operator: {node.op!r}")


_NODE_HANDLERS = {
    Num: ExpressionEvaluator._num,
    Str: ExpressionEvaluator._str,
    Bool: ExpressionEvaluator._bool,
    Ident: ExpressionEvaluator._ident,
    Attr: ExpressionEvaluator._attr,
    MethodCall: ExpressionEvaluator._method,
    Lambda: ExpressionEvaluator._lambda,
    BinOp: ExpressionEvaluator._binop,
    UnaryOp: ExpressionEvaluator._unary,
}


# ---------------------------------------------------------------------------
# Pipeline parsing (extends the basic loader with advanced fields)
# ---------------------------------------------------------------------------

def parse_pipeline(yaml_str: str) -> AdvancedPipelineDef:
    """Parse a YAML pipeline string into an :class:`AdvancedPipelineDef`."""
    data = yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        raise ValueError("Pipeline YAML must be a mapping")
    if "name" not in data:
        raise ValueError("Pipeline must define a 'name'")

    stages: List[AdvancedPipelineStage] = []
    for stage_data in data.get("stages", []) or []:
        stages.append(AdvancedPipelineStage(
            name=stage_data.get("name", "unnamed"),
            tools=list(stage_data.get("tools", []) or []),
            parallel=bool(stage_data.get("parallel", True)),
            condition=stage_data.get("condition"),
            filter=stage_data.get("filter"),
            skip_if=stage_data.get("skip_if"),
            options=stage_data.get("options", {}) or {},
            input=stage_data.get("input"),
            output=stage_data.get("output"),
            config=stage_data.get("config", {}) or {},
        ))

    return AdvancedPipelineDef(
        name=data["name"],
        description=data.get("description", ""),
        target_types=data.get("target_types", ["domain", "ip", "url"]),
        scope_required=bool(data.get("scope_required", False)),
        stages=stages,
        output=data.get("output", {"json": True, "report": True, "terminal": True}),
        variables=data.get("variables", {}) or {},
    )


# ---------------------------------------------------------------------------
# Variable substitution
# ---------------------------------------------------------------------------

_VAR_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def _build_variable_table(pipeline_def: PipelineDef, target: str) -> Dict[str, Any]:
    """Build a flat variable table, resolving nested ``{{var}}`` references.

    ``target`` is always available as ``{{target}}``.
    """
    variables: Dict[str, Any] = {"target": target}
    user_vars = getattr(pipeline_def, "variables", {}) or {}
    # seed
    for k, v in user_vars.items():
        variables[k] = v

    # iteratively resolve references (max 10 passes; no cycles expected)
    for _ in range(10):
        changed = False
        for k, v in list(variables.items()):
            if isinstance(v, str) and _VAR_RE.search(v):
                def _sub(m: re.Match) -> str:
                    name = m.group(1)
                    if name in variables and isinstance(variables[name], str):
                        return variables[name]
                    return m.group(0)
                new_v = _VAR_RE.sub(_sub, v)
                if new_v != v:
                    variables[k] = new_v
                    changed = True
        if not changed:
            break
    return variables


def _resolve_variables(value: Any, variables: Dict[str, Any]) -> Any:
    """Recursively substitute ``{{var}}`` in strings / dicts / lists."""
    if isinstance(value, str):
        def _sub(m: re.Match) -> str:
            name = m.group(1)
            if name in variables:
                return str(variables[name])
            return m.group(0)
        return _VAR_RE.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _resolve_variables(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_variables(v, variables) for v in value]
    return value


# ---------------------------------------------------------------------------
# Output spec helpers
# ---------------------------------------------------------------------------

@dataclass
class OutputSpec:
    name: str
    extract: Optional[str] = None


def _normalize_output_spec(output: Any) -> List[OutputSpec]:
    """Normalize a stage ``output`` field into a list of OutputSpec."""
    if output is None:
        return []
    if isinstance(output, str):
        return [OutputSpec(name=output)]
    if isinstance(output, dict):
        return [OutputSpec(name=output.get("name", ""), extract=output.get("extract"))]
    if isinstance(output, list):
        specs: List[OutputSpec] = []
        for item in output:
            specs.extend(_normalize_output_spec(item))
        return specs
    raise ValueError(f"Invalid output spec: {output!r}")


def _normalize_input_spec(inp: Any) -> List[str]:
    if inp is None:
        return []
    if isinstance(inp, str):
        return [inp]
    if isinstance(inp, list):
        return [str(x) for x in inp]
    raise ValueError(f"Invalid input spec: {inp!r}")


def _coerce_to_strings(items: Any) -> List[str]:
    """Extract plain host/url strings from a list of result dicts or strings."""
    if items is UNDEFINED or items is None:
        return []
    if not isinstance(items, (list, tuple)):
        items = [items]
    out: List[str] = []
    for item in items:
        if isinstance(item, str):
            if item.strip():
                out.append(item.strip())
        elif isinstance(item, dict):
            for key in ("url", "host", "subdomain", "name", "value", "target"):
                if key in item and item[key]:
                    out.append(str(item[key]))
                    break
        elif item is not None:
            out.append(str(item))
    return out


def _store_outputs(stage: AdvancedPipelineStage, results: Dict[str, List[dict]],
                   outputs_map: Dict[str, Any]) -> None:
    """Store this stage's tool results under each declared output name."""
    specs = _normalize_output_spec(stage.output)
    if not specs:
        return
    # combined flat list of all result dicts across tools
    combined: List[Any] = []
    for tool_results in results.values():
        combined.extend(tool_results)

    for spec in specs:
        if not spec.name:
            continue
        if spec.extract:
            extracted: List[Any] = []
            for row in combined:
                if not isinstance(row, dict):
                    continue
                if spec.extract not in row:
                    continue
                val = row[spec.extract]
                if isinstance(val, (list, tuple)):
                    extracted.extend(val)
                elif val is not None:
                    extracted.append(val)
            outputs_map[spec.name] = extracted
        else:
            outputs_map[spec.name] = combined


# ---------------------------------------------------------------------------
# Tool running
# ---------------------------------------------------------------------------

ToolRunner = Callable[[str, str, Dict[str, Any]], List[dict]]


def _default_tool_runner(tool_name: str, target: str, options: Dict[str, Any]) -> List[dict]:
    """Default tool runner: looks up the tool in the orchestrator registry and
    invokes it via subprocess. Returns parsed JSON results (list of dicts).

    Missing tools / failed invocations return an empty list and log a warning
    so the pipeline keeps running.
    """
    # import lazily to avoid a hard import cycle at module load
    try:
        from ..orchestrator.registry import get_tool
    except Exception:  # pragma: no cover - defensive
        log.debug("orchestrator registry unavailable")
        return []

    tool = get_tool(tool_name)
    if tool is None or tool.run_builder is None:
        log.debug(f"Tool {tool_name!r} not registered or has no run_builder")
        return []

    try:
        cmd = tool.run_builder(target, options)
    except Exception as e:
        log.warning(f"Failed to build command for {tool_name!r}: {e}")
        return []
    if not cmd:
        return []

    timeout = int(options.get("timeout", tool.timeout))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        log.warning(f"Tool binary not installed: {tool_name!r} ({cmd[0]})")
        return []
    except subprocess.TimeoutExpired:
        log.warning(f"Tool {tool_name!r} timed out after {timeout}s")
        return []
    except Exception as e:
        log.warning(f"Tool {tool_name!r} failed to execute: {e}")
        return []

    if tool.json_parser is None:
        return []
    try:
        parsed = tool.json_parser(proc.stdout)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
        return []
    except Exception as e:
        log.debug(f"Failed to parse output for {tool_name!r}: {e}")
        return []


# ---------------------------------------------------------------------------
# Advanced pipeline engine
# ---------------------------------------------------------------------------

class AdvancedPipelineEngine:
    """Executes an advanced pipeline definition against a target.

    Usage::

        engine = AdvancedPipelineEngine()
        result = engine.execute(pipeline_def, target)
    """

    def __init__(self, tool_runner: Optional[ToolRunner] = None):
        # Allow injecting a custom tool runner (great for testing). Falls back
        # to the subprocess-based default runner.
        self.tool_runner: ToolRunner = tool_runner or _default_tool_runner

    # ------------------------------------------------------------------
    def execute(self, pipeline_def: PipelineDef, target: str,
                progress_cb: Optional[Callable] = None) -> ExecutionResult:
        """Execute ``pipeline_def`` against ``target``.

        ``progress_cb(stage_name, tool_name, status, payload)`` is called with
        status in ``{'start','done','skip','error'}``.
        """
        result = ExecutionResult()
        variables = _build_variable_table(pipeline_def, target)
        outputs_map: Dict[str, Any] = {}

        stages = getattr(pipeline_def, "stages", []) or []
        for stage in stages:
            adv_stage = self._ensure_advanced_stage(stage)

            # Evaluate condition (skip_if / condition), if any.
            condition_expr = adv_stage.condition or adv_stage.skip_if
            skip_mode = bool(adv_stage.skip_if) and not adv_stage.condition
            if condition_expr:
                try:
                    evaluator = ExpressionEvaluator(outputs_map, strict=False)
                    cond_result = bool(evaluator.eval(condition_expr))
                except ExpressionError as e:
                    msg = f"Stage {adv_stage.name!r}: invalid condition {condition_expr!r}: {e}"
                    result.errors.append(msg)
                    log.error(msg)
                    result.stages_skipped.append(adv_stage.name)
                    result.skipped_reasons[adv_stage.name] = f"invalid condition: {e}"
                    if progress_cb:
                        progress_cb(adv_stage.name, "", "error", {"error": str(e)})
                    continue

                # condition: False -> skip ; skip_if: True -> skip
                should_skip = (not cond_result) if not skip_mode else cond_result
                if should_skip:
                    reason = (
                        f"condition false: {condition_expr}"
                        if not skip_mode
                        else f"skip_if true: {condition_expr}"
                    )
                    result.stages_skipped.append(adv_stage.name)
                    result.skipped_reasons[adv_stage.name] = reason
                    log.info(f"Stage {adv_stage.name!r} skipped ({reason})")
                    if progress_cb:
                        progress_cb(adv_stage.name, "", "skip", {"reason": reason})
                    continue

            # Resolve variables in per-tool config (options + config merged).
            merged_config = self._merge_config(adv_stage)
            resolved_config = _resolve_variables(merged_config, variables)

            # Gather inputs from named outputs.
            input_names = _normalize_input_spec(adv_stage.input)
            stage_input: Dict[str, Any] = {}
            missing_inputs: List[str] = []
            for iname in input_names:
                if iname in outputs_map:
                    stage_input[iname] = outputs_map[iname]
                else:
                    missing_inputs.append(iname)
            if missing_inputs:
                msg = (f"Stage {adv_stage.name!r}: input(s) not found: "
                       f"{', '.join(missing_inputs)}")
                result.errors.append(msg)
                log.warning(msg)

            result.stages_executed.append(adv_stage.name)
            tool_results: Dict[str, List[dict]] = {}

            for tool_name in adv_stage.tools:
                tool_opts = dict(resolved_config.get(tool_name, {}))
                # Inject input data so tools/runners can consume it.
                if stage_input:
                    # Primary input (first named input) as items list.
                    first_input = next(iter(stage_input.values()))
                    tool_opts["input_items"] = _coerce_to_strings(first_input)
                    tool_opts["input"] = stage_input
                    # If the default runner is in use, write a temp file it
                    # can pick up via the 'input_file' option.
                    tool_opts.setdefault(
                        "input_file", self._write_input_file(tool_opts["input_items"])
                    )

                if progress_cb:
                    progress_cb(adv_stage.name, tool_name, "start", {})
                try:
                    out = self.tool_runner(tool_name, target, tool_opts)
                    if not isinstance(out, list):
                        out = [] if out is None else [out]
                except Exception as e:
                    msg = f"Stage {adv_stage.name!r} tool {tool_name!r} error: {e}"
                    result.errors.append(msg)
                    log.error(msg)
                    out = []
                    if progress_cb:
                        progress_cb(adv_stage.name, tool_name, "error", {"error": str(e)})

                tool_results[tool_name] = out
                if progress_cb:
                    progress_cb(adv_stage.name, tool_name, "done",
                               {"count": len(out)})

            # Store named outputs for later stages.
            _store_outputs(adv_stage, tool_results, outputs_map)

        result.outputs = outputs_map
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _ensure_advanced_stage(stage: PipelineStage) -> AdvancedPipelineStage:
        if isinstance(stage, AdvancedPipelineStage):
            return stage
        # Promote a basic PipelineStage to an advanced one (no input/output).
        return AdvancedPipelineStage(
            name=stage.name, tools=list(stage.tools), parallel=stage.parallel,
            condition=stage.condition, filter=stage.filter, skip_if=stage.skip_if,
            options=dict(stage.options), input=None, output=None, config={},
        )

    @staticmethod
    def _merge_config(stage: AdvancedPipelineStage) -> Dict[str, Dict[str, Any]]:
        """Merge per-tool options (``options``) and ``config`` (config wins)."""
        merged: Dict[str, Dict[str, Any]] = {}
        for tool_name in set(list(stage.options.keys()) + list(stage.config.keys())):
            opts = {}
            opts.update(stage.options.get(tool_name, {}) or {})
            opts.update(stage.config.get(tool_name, {}) or {})
            merged[tool_name] = opts
        return merged

    @staticmethod
    def _write_input_file(items: List[str]) -> str:
        if not items:
            return "/dev/stdin"
        try:
            fd, path = tempfile.mkstemp(prefix="gungnir-input-", suffix=".txt")
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(items) + "\n")
            return path
        except Exception:
            return "/dev/stdin"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_pipeline(yaml_str: str, extra_tools: Optional[Set[str]] = None) -> List[str]:
    """Validate a pipeline YAML string. Returns a list of error messages
    (empty list means valid).

    Checks:
    - YAML parses and has a name.
    - Every stage has a name.
    - Every referenced tool is known (registry + EXTRA_TOOL_NAMES + extra_tools).
    - Every stage ``input`` refers to an output name declared by an earlier stage.
    - Stage ``condition`` / ``skip_if`` are parseable expressions.
    - Output names are not declared by multiple stages.
    - ``{{var}}`` references in stage configs resolve against pipeline variables
      (+ the built-in ``target``).
    """
    errors: List[str] = []

    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if not isinstance(data, dict):
        return ["Pipeline YAML must be a mapping"]
    if "name" not in data or not data["name"]:
        errors.append("Pipeline must define a non-empty 'name'")

    known_tools: Set[str] = set(EXTRA_TOOL_NAMES)
    if extra_tools:
        known_tools |= set(extra_tools)
    try:
        from ..orchestrator.registry import TOOL_REGISTRY
        known_tools |= set(TOOL_REGISTRY.keys())
    except Exception:  # pragma: no cover - defensive
        pass

    variables: Set[str] = {"target"}
    user_vars = data.get("variables", {}) or {}
    if isinstance(user_vars, dict):
        variables |= set(user_vars.keys())
    else:
        errors.append("'variables' must be a mapping")

    stages_data = data.get("stages", []) or []
    if not isinstance(stages_data, list):
        errors.append("'stages' must be a list")
        return errors

    declared_outputs: Set[str] = set()
    prior_outputs: Set[str] = set()

    for idx, stage_data in enumerate(stages_data):
        if not isinstance(stage_data, dict):
            errors.append(f"Stage #{idx + 1}: must be a mapping")
            continue
        label = stage_data.get("name") or f"stage #{idx + 1}"

        # name
        if not stage_data.get("name"):
            errors.append(f"Stage #{idx + 1}: missing 'name'")

        # tools exist
        for tool_name in stage_data.get("tools", []) or []:
            if tool_name not in known_tools:
                errors.append(
                    f"Stage {label!r}: unknown tool {tool_name!r}"
                )

        # inputs reference prior outputs
        inp = stage_data.get("input")
        input_names: List[str] = []
        try:
            input_names = _normalize_input_spec(inp)
        except ValueError as e:
            errors.append(f"Stage {label!r}: invalid input spec: {e}")
        for iname in input_names:
            if iname not in prior_outputs:
                errors.append(
                    f"Stage {label!r}: input {iname!r} is not produced by any "
                    f"earlier stage"
                )

        # conditions are valid expressions
        for cond_field in ("condition", "skip_if", "filter"):
            expr = stage_data.get(cond_field)
            if expr is None:
                continue
            if not isinstance(expr, str):
                errors.append(f"Stage {label!r}: {cond_field} must be a string")
                continue
            try:
                parse_expression(expr)
            except ExpressionError as e:
                errors.append(
                    f"Stage {label!r}: invalid {cond_field} expression "
                    f"{expr!r}: {e}"
                )

        # output spec validity
        out = stage_data.get("output")
        try:
            specs = _normalize_output_spec(out)
        except ValueError as e:
            errors.append(f"Stage {label!r}: invalid output spec: {e}")
            specs = []
        for spec in specs:
            if not spec.name:
                errors.append(f"Stage {label!r}: output spec missing 'name'")
                continue
            if spec.name in declared_outputs:
                errors.append(
                    f"Stage {label!r}: output name {spec.name!r} already "
                    f"declared by another stage"
                )
            declared_outputs.add(spec.name)

        # variable references in stage options/config resolve
        for cfg_field in ("options", "config"):
            cfg = stage_data.get(cfg_field, {}) or {}
            _check_var_refs(cfg, variables, label, cfg_field, errors)

        # update prior_outputs for subsequent stages
        prior_outputs |= {s.name for s in specs if s.name}

    return errors


def _check_var_refs(value: Any, variables: Set[str], label: str,
                    field: str, errors: List[str]) -> None:
    if isinstance(value, str):
        for m in _VAR_RE.finditer(value):
            if m.group(1) not in variables:
                errors.append(
                    f"Stage {label!r}: undefined variable {m.group(1)!r} "
                    f"in {field}"
                )
    elif isinstance(value, dict):
        for v in value.values():
            _check_var_refs(v, variables, label, field, errors)
    elif isinstance(value, list):
        for v in value:
            _check_var_refs(v, variables, label, field, errors)


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

def dry_run_pipeline(pipeline_def: PipelineDef, target: str) -> str:
    """Render a human-readable execution plan for ``pipeline_def`` against
    ``target``. Conditions are evaluated against an *empty* output state, so
    any condition that depends on prior outputs reports as 'false (empty state)'
    and the stage is shown as 'would skip'.
    """
    variables = _build_variable_table(pipeline_def, target)
    lines: List[str] = []
    bar = "=" * 72
    lines.append(bar)
    lines.append(f"DRY RUN: {getattr(pipeline_def, 'name', '<unnamed>')}")
    desc = getattr(pipeline_def, "description", "")
    if desc:
        lines.append(f"description: {desc}")
    lines.append(f"target: {target}")
    if variables:
        shown = {k: v for k, v in variables.items() if k != "target" or v != target}
        if shown:
            lines.append(f"variables: {shown}")
    lines.append(bar)
    lines.append("")

    empty_evaluator = ExpressionEvaluator({}, strict=False)
    prior_outputs: Set[str] = set()

    stages = getattr(pipeline_def, "stages", []) or []
    for idx, stage in enumerate(stages, 1):
        adv = AdvancedPipelineEngine._ensure_advanced_stage(stage)
        lines.append(f"[Stage {idx}] {adv.name}")
        lines.append(f"  tools:    {', '.join(adv.tools) if adv.tools else '(none)'}")
        lines.append(f"  parallel: {adv.parallel}")

        input_names = _normalize_input_spec(adv.input)
        if input_names:
            avail = [n for n in input_names if n in prior_outputs]
            missing = [n for n in input_names if n not in prior_outputs]
            lines.append(f"  input:    {input_names}")
            if missing:
                lines.append(
                    f"            (not yet produced in empty state: {missing})"
                )
            if avail:
                lines.append(f"            (available from earlier stage: {avail})")

        specs = _normalize_output_spec(adv.output)
        if specs:
            for s in specs:
                if s.extract:
                    lines.append(f"  output:   {s.name} (extract field: {s.extract})")
                else:
                    lines.append(f"  output:   {s.name}")
            prior_outputs |= {s.name for s in specs}

        merged = AdvancedPipelineEngine._merge_config(adv)
        if merged:
            shown_cfg = _resolve_variables(merged, variables)
            lines.append(f"  config:   {shown_cfg}")

        cond_expr = adv.condition or adv.skip_if
        if cond_expr:
            skip_mode = bool(adv.skip_if) and not adv.condition
            try:
                result = bool(empty_evaluator.eval(cond_expr))
            except ExpressionError as e:
                lines.append(f"  condition: {cond_expr}  -> ERROR: {e}")
                lines.append("  >> would skip (invalid condition)")
                lines.append("")
                continue
            if not skip_mode:
                if result:
                    lines.append(f"  condition: {cond_expr}  -> true  >> would RUN")
                else:
                    lines.append(
                        f"  condition: {cond_expr}  -> false (empty state)  "
                        f">> would SKIP"
                    )
            else:
                if result:
                    lines.append(
                        f"  skip_if:   {cond_expr}  -> true (empty state)  "
                        f">> would SKIP"
                    )
                else:
                    lines.append(f"  skip_if:   {cond_expr}  -> false  >> would RUN")
        else:
            lines.append("  >> would RUN (no condition)")

        lines.append("")

    lines.append(bar)
    lines.append("end of plan")
    return "\n".join(lines)
