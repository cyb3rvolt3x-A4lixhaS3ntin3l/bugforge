"""Tests for the advanced pipeline execution engine."""
import pytest

from gungnir.core.advanced_pipeline import (
    AdvancedPipelineEngine,
    AdvancedPipelineStage,
    ExecutionResult,
    ExpressionError,
    ExpressionEvaluator,
    UNDEFINED,
    dry_run_pipeline,
    parse_pipeline,
    validate_pipeline,
)


# ---------------------------------------------------------------------------
# Expression evaluator
# ---------------------------------------------------------------------------

class TestExpressionEvaluator:
    def setup_method(self):
        self.ctx = {
            "tech": ["wordpress", "nginx"],
            "live_hosts": [{"url": "http://x"}, {"url": "http://y"}],
            "endpoints": ["/api/users", "/home", "/login"],
            "findings": [],
            "graphql_detected": True,
        }
        self.ev = ExpressionEvaluator(self.ctx)

    def test_contains_and_count(self):
        assert self.ev.eval("tech contains 'wordpress' AND live_hosts.count > 0")

    def test_contains_false(self):
        assert not self.ev.eval("tech contains 'apache'")

    def test_any_lambda(self):
        assert self.ev.eval("endpoints.any(e -> e.contains('/api/'))")

    def test_any_lambda_false(self):
        assert not self.ev.eval("endpoints.any(e -> e.contains('/admin/'))")

    def test_all_lambda(self):
        assert self.ev.eval("endpoints.all(e -> e.contains('/'))")

    def test_all_lambda_false(self):
        assert not self.ev.eval("endpoints.all(e -> e.contains('api'))")

    def test_count_eq(self):
        assert self.ev.eval("findings.count == 0")

    def test_bool_literal(self):
        assert self.ev.eval("graphql_detected == true")

    def test_not(self):
        assert self.ev.eval("NOT tech contains 'rails'")

    def test_or(self):
        assert self.ev.eval("tech contains 'apache' OR findings.count == 0")

    def test_parens(self):
        assert self.ev.eval("(tech contains 'wordpress') AND (live_hosts.count > 1)")

    def test_comparisons(self):
        assert self.ev.eval("live_hosts.count >= 2")
        assert self.ev.eval("live_hosts.count < 5")
        assert not self.ev.eval("live_hosts.count != 2")

    def test_matches_regex(self):
        ev = ExpressionEvaluator({"url": "https://api.example.com"})
        assert ev.eval("url matches 'api\\\\.example'")

    def test_empty_state_is_tolerant(self):
        ev = ExpressionEvaluator({}, strict=False)
        assert not self.ev.eval("tech contains 'wordpress' AND live_hosts.count > 0")
        # count of missing -> 0
        assert ev.eval("findings.count == 0")

    def test_strict_raises_on_undefined(self):
        ev = ExpressionEvaluator({}, strict=True)
        with pytest.raises(ExpressionError):
            ev.eval("missing == 1")

    def test_invalid_expression_raises(self):
        with pytest.raises(ExpressionError):
            ExpressionEvaluator({}).eval("tech contains")
        with pytest.raises(ExpressionError):
            ExpressionEvaluator({}).eval("(tech contains 'x'")

    def test_no_eval_exec(self):
        # Make sure the evaluator does not honor python expressions
        ev = ExpressionEvaluator({})
        with pytest.raises(ExpressionError):
            ev.eval("__import__('os')")


# ---------------------------------------------------------------------------
# Pipeline parsing
# ---------------------------------------------------------------------------

class TestParsePipeline:
    def test_basic(self):
        y = """
name: P
description: d
stages:
  - name: recon
    tools: [subfinder]
    output: assets
  - name: probe
    tools: [httpx]
    input: assets
    output:
      - name: live_hosts
      - name: tech
        extract: tech
"""
        p = parse_pipeline(y)
        assert p.name == "P"
        assert len(p.stages) == 2
        assert isinstance(p.stages[0], AdvancedPipelineStage)
        assert p.stages[1].input == "assets"
        specs = p.stages[1].output
        assert isinstance(specs, list)

    def test_variables(self):
        y = """
name: P
variables:
  sev: "high,critical"
stages:
  - name: s
    tools: [nuclei]
"""
        p = parse_pipeline(y)
        assert p.variables == {"sev": "high,critical"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidatePipeline:
    def test_valid(self):
        y = """
name: P
stages:
  - name: recon
    tools: [subfinder]
    output: assets
  - name: probe
    tools: [httpx]
    input: assets
    output: live_hosts
"""
        assert validate_pipeline(y) == []

    def test_missing_name(self):
        assert validate_pipeline("stages: []\n") == [
            "Pipeline must define a non-empty 'name'"
        ]

    def test_missing_stage_name(self):
        errs = validate_pipeline("name: P\nstages:\n  - tools: [subfinder]\n")
        assert any("missing 'name'" in e for e in errs)

    def test_unknown_tool(self):
        errs = validate_pipeline("name: P\nstages:\n  - name: s\n    tools: [nope]\n")
        assert any("unknown tool" in e for e in errs)

    def test_bad_input_ref(self):
        errs = validate_pipeline(
            "name: P\nstages:\n  - name: s\n    tools: [subfinder]\n    input: ghost\n"
        )
        assert any("input 'ghost'" in e for e in errs)

    def test_invalid_condition(self):
        errs = validate_pipeline(
            'name: P\nstages:\n  - name: s\n    tools: [subfinder]\n    condition: "tech contains"\n'
        )
        assert any("invalid condition" in e for e in errs)

    def test_duplicate_output(self):
        y = """
name: P
stages:
  - name: a
    tools: [subfinder]
    output: shared
  - name: b
    tools: [assetfinder]
    output: shared
"""
        errs = validate_pipeline(y)
        assert any("already declared" in e for e in errs)

    def test_undefined_variable(self):
        y = '''
name: P
stages:
  - name: s
    tools: [subfinder]
    config:
      subfinder:
        x: "{{nope}}"
'''
        errs = validate_pipeline(y)
        assert any("undefined variable 'nope'" in e for e in errs)

    def test_extra_tools(self):
        y = "name: P\nstages:\n  - name: s\n    tools: [my-custom]\n"
        assert validate_pipeline(y)  # unknown
        assert validate_pipeline(y, extra_tools={"my-custom"}) == []


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_plan_text(self):
        y = """
name: Demo
description: a demo
stages:
  - name: recon
    tools: [subfinder]
    output: assets
  - name: deep
    tools: [nuclei]
    condition: "assets.count > 0"
"""
        out = dry_run_pipeline(parse_pipeline(y), "example.com")
        assert "DRY RUN: Demo" in out
        assert "[Stage 1] recon" in out
        assert "would RUN (no condition)" in out
        # condition depends on prior output -> false in empty state -> skip
        assert "would SKIP" in out
        assert "example.com" in out


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

class TestExecution:
    def _runner(self, tool, target, options):
        if tool == "subfinder":
            return [{"subdomain": f"a.{target}"}, {"subdomain": f"b.{target}"}]
        if tool == "httpx":
            assert options.get("input_items"), "input items not wired"
            return [
                {"url": f"http://{s}", "tech": ["nginx", "wordpress"]}
                for s in options["input_items"]
            ]
        if tool == "nuclei":
            return [{"template": "CVE-1", "severity": "high"}]
        return []

    def test_chain_and_conditions(self):
        y = """
name: Chain
variables:
  sev: "high,critical"
stages:
  - name: recon
    tools: [subfinder]
    output: assets
  - name: probe
    tools: [httpx]
    input: assets
    output:
      - name: live_hosts
      - name: tech
        extract: tech
  - name: deep
    tools: [nuclei]
    input: live_hosts
    condition: "tech contains 'wordpress' AND live_hosts.count > 0"
    config:
      nuclei:
        severity: "{{sev}}"
  - name: skipped
    tools: [dalfox]
    condition: "tech contains 'drupal'"
"""
        eng = AdvancedPipelineEngine(tool_runner=self._runner)
        res = eng.execute(parse_pipeline(y), "example.com")
        assert isinstance(res, ExecutionResult)
        assert res.stages_executed == ["recon", "probe", "deep"]
        assert res.stages_skipped == ["skipped"]
        assert res.errors == []
        assert len(res.outputs["live_hosts"]) == 2
        assert "wordpress" in res.outputs["tech"]

    def test_skip_if(self):
        y = """
name: S
stages:
  - name: a
    tools: [subfinder]
    output: assets
  - name: b
    tools: [nuclei]
    skip_if: "assets.count > 0"
"""
        eng = AdvancedPipelineEngine(tool_runner=self._runner)
        res = eng.execute(parse_pipeline(y), "x.com")
        # assets has 2 -> skip_if true -> skip
        assert "b" in res.stages_skipped

    def test_progress_cb(self):
        y = "name: P\nstages:\n  - name: s\n    tools: [subfinder]\n    output: a\n"
        events = []

        def cb(stage, tool, status, payload):
            events.append((stage, tool, status))

        eng = AdvancedPipelineEngine(tool_runner=self._runner)
        eng.execute(parse_pipeline(y), "x.com", progress_cb=cb)
        assert ("s", "subfinder", "start") in events
        assert ("s", "subfinder", "done") in events
