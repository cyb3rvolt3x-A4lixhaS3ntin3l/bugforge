"""
Custom tool registration — lets researchers register their own scripts
and binaries as Gungnir tools via YAML definitions.

Custom tool YAML format:
  name: my-scanner
  description: My custom vulnerability scanner
  category: vuln_scan
  type: executable
  binary: /path/to/binary
  command: "{binary} --target {target} --json"
  parser: json
  timeout: 120
  wave: deep_scan
  applies_to: [domain, url]
"""
from __future__ import annotations
import os
import yaml
import shutil
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path
from ..utils.logger import get_logger

log = get_logger()


@dataclass
class CustomTool:
    name: str
    description: str = ""
    category: str = "vuln_scan"
    type: str = "executable"       # executable | python | bash
    binary: str = ""                # path to binary/script
    command: str = ""               # command template with {binary}, {target}, {options}
    parser: str = "json"            # json | line-by-line | regex | none
    parser_pattern: Optional[str] = None
    parser_groups: List[str] = field(default_factory=list)
    timeout: int = 120
    wave: str = "deep_scan"         # discovery | deep_scan
    applies_to: List[str] = field(default_factory=lambda: ["domain", "ip", "url"])
    requires_web: bool = True
    config_schema: List[Dict] = field(default_factory=list)
    file_path: Optional[str] = None


class CustomToolLoader:
    """Loads custom tool definitions from YAML files."""

    def __init__(self, tools_dir: str):
        self.tools_dir = Path(tools_dir)
        self.custom_dir = self.tools_dir / "custom"
        self.scripts_dir = self.tools_dir / "scripts"
        self.custom_dir.mkdir(parents=True, exist_ok=True)
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, CustomTool] = {}

    def load_all(self) -> Dict[str, CustomTool]:
        """Load all custom tool definitions."""
        self._cache.clear()
        for yaml_file in sorted(self.custom_dir.glob("*.yaml")):
            try:
                tool = self._load_file(str(yaml_file))
                if tool:
                    tool.file_path = str(yaml_file)
                    self._cache[tool.name] = tool
            except Exception as e:
                log.error(f"Failed to load custom tool {yaml_file}: {e}")
        return self._cache

    def _load_file(self, path: str) -> Optional[CustomTool]:
        """Load a single custom tool YAML."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "name" not in data:
            return None

        return CustomTool(
            name=data["name"],
            description=data.get("description", ""),
            category=data.get("category", "vuln_scan"),
            type=data.get("type", "executable"),
            binary=self._resolve_path(data.get("binary", "")),
            command=data.get("command", ""),
            parser=data.get("parser", "none"),
            parser_pattern=data.get("parser_pattern"),
            parser_groups=data.get("parser_groups", []),
            timeout=data.get("timeout", 120),
            wave=data.get("wave", "deep_scan"),
            applies_to=data.get("applies_to", ["domain", "ip", "url"]),
            requires_web=data.get("requires_web", True),
            config_schema=data.get("config_schema", []),
        )

    def _resolve_path(self, path: str) -> str:
        """Resolve a path, expanding ~ and relative paths."""
        if not path:
            return ""
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = str(self.scripts_dir / path)
        return path

    def get(self, name: str) -> Optional[CustomTool]:
        """Get a custom tool by name."""
        if not self._cache:
            self.load_all()
        return self._cache.get(name)

    def list_names(self) -> List[str]:
        """List all custom tool names."""
        if not self._cache:
            self.load_all()
        return list(self._cache.keys())

    def register(self, name: str, description: str, category: str,
                 binary: str, command: str = "", parser: str = "none",
                 timeout: int = 120, wave: str = "deep_scan",
                 tool_type: str = "executable",
                 applies_to: List[str] = None) -> str:
        """Register a new custom tool. Returns the YAML file path."""
        data = {
            "name": name,
            "description": description,
            "category": category,
            "type": tool_type,
            "binary": binary,
            "command": command or f"{{binary}} {{target}}",
            "parser": parser,
            "timeout": timeout,
            "wave": wave,
            "applies_to": applies_to or ["domain", "ip", "url"],
        }

        safe_name = "".join(c for c in name if c.isalnum() or c in "-_").lower()
        path = self.custom_dir / f"{safe_name}.yaml"

        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        self.load_all()
        return str(path)

    def delete(self, name: str) -> bool:
        """Delete a custom tool."""
        tool = self.get(name)
        if not tool or not tool.file_path:
            return False
        os.remove(tool.file_path)
        if name in self._cache:
            del self._cache[name]
        return True

    def build_command(self, tool: CustomTool, target: str, options: Dict) -> List[str]:
        """Build the command list for running a custom tool."""
        if not tool.command:
            # Default: binary target
            return [tool.binary, target]

        # Substitute variables
        cmd_str = tool.command
        cmd_str = cmd_str.replace("{binary}", tool.binary)
        cmd_str = cmd_str.replace("{target}", target)

        # Parse into list (simple split — doesn't handle quoted args perfectly)
        import shlex
        return shlex.split(cmd_str)

    def parse_output(self, tool: CustomTool, stdout: str) -> List[dict]:
        """Parse tool output based on the parser type."""
        if tool.parser == "json":
            return self._parse_json(stdout)
        elif tool.parser == "line-by-line":
            return self._parse_lines(stdout, tool)
        elif tool.parser == "regex":
            return self._parse_regex(stdout, tool)
        else:
            return [{"type": "raw_output", "output": stdout[:500], "source": tool.name}]

    @staticmethod
    def _parse_json(stdout: str) -> List[dict]:
        import json
        results = []
        for line in stdout.strip().splitlines():
            try:
                d = json.loads(line)
                if isinstance(d, list):
                    results.extend(d)
                else:
                    results.append(d)
            except json.JSONDecodeError:
                continue
        # Also try parsing as a single JSON array
        if not results:
            try:
                data = json.loads(stdout.strip())
                if isinstance(data, list):
                    results = data
                else:
                    results = [data]
            except json.JSONDecodeError:
                pass
        return results

    @staticmethod
    def _parse_lines(stdout: str, tool: CustomTool) -> List[dict]:
        return [{"type": "finding", "value": line.strip(), "source": tool.name}
                for line in stdout.strip().splitlines() if line.strip()]

    @staticmethod
    def _parse_regex(stdout: str, tool: CustomTool) -> List[dict]:
        import re
        if not tool.parser_pattern:
            return []
        results = []
        for m in re.finditer(tool.parser_pattern, stdout):
            groups = m.groups()
            finding = {"source": tool.name}
            for i, group_name in enumerate(tool.parser_groups):
                if i < len(groups):
                    finding[group_name] = groups[i]
            results.append(finding)
        return results

    def to_dict(self, tool: CustomTool) -> dict:
        """Convert to serializable dict."""
        return {
            "name": tool.name,
            "description": tool.description,
            "category": tool.category,
            "type": tool.type,
            "binary": tool.binary,
            "command": tool.command,
            "parser": tool.parser,
            "timeout": tool.timeout,
            "wave": tool.wave,
            "applies_to": tool.applies_to,
            "requires_web": tool.requires_web,
            "available": os.path.isfile(tool.binary) and os.access(tool.binary, os.X_OK) if tool.binary else False,
        }
