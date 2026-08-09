"""
Pipeline loader — parses YAML pipeline definitions and converts them
into executable stage plans. Supports custom pipelines, conditions,
per-tool options, and parallel/sequential stages.

Pipeline YAML format:
  name: My Pipeline
  description: What it does
  target_types: [domain, ip, url]
  scope_required: true

  stages:
    - name: recon
      tools: [subfinder, assetfinder]
      parallel: true
      options:
        subfinder:
          timeout: 60
    - name: deep-scan
      tools: [nuclei, dalfox, ffuf]
      parallel: true
      condition: "assets > 0"
      options:
        nuclei:
          severity: "high,critical"
"""
from __future__ import annotations
import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path
from ..utils.logger import get_logger

log = get_logger()


@dataclass
class PipelineStage:
    name: str
    tools: List[str] = field(default_factory=list)
    parallel: bool = True
    condition: Optional[str] = None
    filter: Optional[str] = None
    skip_if: Optional[str] = None
    options: Dict[str, Dict] = field(default_factory=dict)


@dataclass
class PipelineDef:
    name: str
    description: str = ""
    target_types: List[str] = field(default_factory=lambda: ["domain", "ip", "url"])
    scope_required: bool = False
    stages: List[PipelineStage] = field(default_factory=list)
    output: Dict[str, bool] = field(default_factory=lambda: {"json": True, "report": True, "terminal": True})
    file_path: Optional[str] = None


class PipelineLoader:
    """Loads pipelines from YAML files in the pipelines directory."""

    def __init__(self, pipelines_dir: str):
        self.pipelines_dir = Path(pipelines_dir)
        self.pipelines_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, PipelineDef] = {}

    def load_all(self) -> Dict[str, PipelineDef]:
        """Load all pipelines from the pipelines directory."""
        self._cache.clear()

        # Load built-in pipelines first
        builtin_dir = Path(__file__).parent.parent / "pipelines"
        for yaml_file in sorted(builtin_dir.glob("*.yaml")):
            try:
                pdef = self._load_file(str(yaml_file))
                if pdef:
                    self._cache[pdef.name] = pdef
            except Exception as e:
                log.debug(f"Failed to load built-in pipeline {yaml_file}: {e}")

        # Load user pipelines (override built-ins with same name)
        for yaml_file in sorted(self.pipelines_dir.glob("*.yaml")):
            try:
                pdef = self._load_file(str(yaml_file))
                if pdef:
                    pdef.file_path = str(yaml_file)
                    self._cache[pdef.name] = pdef
            except Exception as e:
                log.error(f"Failed to load pipeline {yaml_file}: {e}")

        return self._cache

    def _load_file(self, path: str) -> Optional[PipelineDef]:
        """Load a single pipeline YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "name" not in data:
            return None

        stages = []
        for stage_data in data.get("stages", []):
            stages.append(PipelineStage(
                name=stage_data.get("name", "unnamed"),
                tools=stage_data.get("tools", []),
                parallel=stage_data.get("parallel", True),
                condition=stage_data.get("condition"),
                filter=stage_data.get("filter"),
                skip_if=stage_data.get("skip_if"),
                options=stage_data.get("options", {}),
            ))

        return PipelineDef(
            name=data["name"],
            description=data.get("description", ""),
            target_types=data.get("target_types", ["domain", "ip", "url"]),
            scope_required=data.get("scope_required", False),
            stages=stages,
            output=data.get("output", {"json": True, "report": True, "terminal": True}),
            file_path=path,
        )

    def get(self, name: str) -> Optional[PipelineDef]:
        """Get a pipeline by name."""
        if not self._cache:
            self.load_all()
        return self._cache.get(name)

    def list_names(self) -> List[str]:
        """List all pipeline names."""
        if not self._cache:
            self.load_all()
        return list(self._cache.keys())

    def create(self, name: str, description: str, stages: List[Dict],
               target_types: List[str] = None, scope_required: bool = False) -> str:
        """Create a new pipeline YAML file. Returns the file path."""
        data = {
            "name": name,
            "description": description,
            "target_types": target_types or ["domain", "ip", "url"],
            "scope_required": scope_required,
            "stages": stages,
            "output": {"json": True, "report": True, "terminal": True},
        }

        # Sanitize filename
        safe_name = "".join(c for c in name if c.isalnum() or c in "-_").lower()
        path = self.pipelines_dir / f"{safe_name}.yaml"

        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        # Reload cache
        self.load_all()
        return str(path)

    def delete(self, name: str) -> bool:
        """Delete a pipeline. Only user pipelines can be deleted."""
        pdef = self.get(name)
        if not pdef or not pdef.file_path:
            return False

        # Don't delete built-in pipelines
        builtin_dir = str(Path(__file__).parent.parent / "pipelines")
        if pdef.file_path.startswith(builtin_dir):
            return False

        os.remove(pdef.file_path)
        if name in self._cache:
            del self._cache[name]
        return True

    def to_dict(self, pdef: PipelineDef) -> dict:
        """Convert a PipelineDef to a serializable dict."""
        return {
            "name": pdef.name,
            "description": pdef.description,
            "target_types": pdef.target_types,
            "scope_required": pdef.scope_required,
            "stages": [
                {
                    "name": s.name,
                    "tools": s.tools,
                    "parallel": s.parallel,
                    "condition": s.condition,
                    "options": s.options,
                }
                for s in pdef.stages
            ],
            "output": pdef.output,
        }
