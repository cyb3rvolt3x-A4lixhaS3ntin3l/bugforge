"""
Configuration — sensible defaults, zero config required.
Everything can be overridden via environment variables or config file.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # Paths
    home_dir: Path = field(default_factory=lambda: Path(os.environ.get("BUGFORGE_HOME", Path.home() / ".bugforge")))
    bin_dir: Path = field(default_factory=lambda: Path())
    template_dir: Path = field(default_factory=lambda: Path())
    wordlist_dir: Path = field(default_factory=lambda: Path())
    payload_dir: Path = field(default_factory=lambda: Path())
    db_path: Path = field(default_factory=lambda: Path())

    # Execution
    max_concurrent: int = 20
    default_timeout: int = 300
    rate_limit_per_host: int = 50  # requests per second per host

    # Waves
    wave1_timeout: int = 120
    wave2_timeout: int = 600

    # Web UI
    web_host: str = "127.0.0.1"
    web_port: int = 8888

    # Scope
    auto_install: bool = True
    verify_criticals: bool = True
    min_confidence: float = 0.2

    def __post_init__(self):
        self.bin_dir = self.home_dir / "bin"
        self.template_dir = self.home_dir / "templates"
        self.wordlist_dir = self.home_dir / "wordlists"
        self.payload_dir = self.home_dir / "payloads"
        self.db_path = self.home_dir / "bugforge.db"
        self.home_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(exist_ok=True)
        self.template_dir.mkdir(exist_ok=True)
        self.wordlist_dir.mkdir(exist_ok=True)
        self.payload_dir.mkdir(exist_ok=True)


def get_config() -> Config:
    return Config()
