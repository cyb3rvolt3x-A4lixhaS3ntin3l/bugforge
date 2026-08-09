"""
CVSS v3.1 calculator (base score only).

Computes the base score from the 8 base metrics and produces the standard
vector string. This is a self-contained implementation — no external deps.

Reference: https://www.first.org/cvss/specification-citation
"""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Dict, Optional


# Metric value -> numeric weight (CVSS v3.1 spec tables)
_ATTACK_VECTOR = {"X": 0.85, "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY = {"X": 0.77, "L": 0.77, "H": 0.44}
_PRIVILEGES = {"X": 0.85, "N": 0.85, "L": 0.62, "H": 0.27}
_USER_INTERACTION = {"X": 0.85, "N": 0.85, "R": 0.62}
_SCOPE = {"X": 0.0, "U": 0.0, "C": 1.0}  # Changed scope boolean (1.0 = changed)
_CONFIDENTIALITY = {"X": 0.0, "H": 0.56, "L": 0.22, "N": 0.0}
_INTEGRITY = {"X": 0.0, "H": 0.56, "L": 0.22, "N": 0.0}
_AVAILABILITY = {"X": 0.0, "H": 0.56, "L": 0.22, "N": 0.0}

_METRIC_LABELS = {
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "R": "Required"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "I": ("Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "A": ("Availability", {"H": "High", "L": "Low", "N": "None"}),
}


@dataclass
class CvssVector:
    """A CVSS v3.1 vector string, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'."""
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "H"
    I: str = "H"
    A: str = "H"

    def to_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
                f"/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}")

    @classmethod
    def parse(cls, vector: str) -> "CvssVector":
        v = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
        parts = {p.split(":")[0]: p.split(":")[1] for p in v.split("/") if ":" in p}
        return cls(
            AV=parts.get("AV", "N"), AC=parts.get("AC", "L"), PR=parts.get("PR", "N"),
            UI=parts.get("UI", "N"), S=parts.get("S", "U"), C=parts.get("C", "H"),
            I=parts.get("I", "H"), A=parts.get("A", "H"),
        )


class Cvss31:
    """Compute CVSS v3.1 base scores."""

    @staticmethod
    def base_score(vector: CvssVector) -> float:
        av = _ATTACK_VECTOR[vector.AV]
        ac = _ATTACK_COMPLEXITY[vector.AC]
        pr_unchanged = _PRIVILEGES[vector.PR]
        pr_changed = {"N": 0.85, "L": 0.68, "H": 0.50}[vector.PR]
        ui = _USER_INTERACTION[vector.UI]
        scope_changed = _SCOPE[vector.S]
        c = _CONFIDENTIALITY[vector.C]
        i = _INTEGRITY[vector.I]
        a = _AVAILABILITY[vector.A]

        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope_changed:
            isc = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15
        else:
            isc = isc_base * 6.42

        pr = pr_changed if scope_changed else pr_unchanged
        exploitability = 8.22 * av * ac * pr * ui

        if isc <= 0:
            return 0.0
        if scope_changed:
            score = min(10.0, 1.08 * (isc + exploitability))
        else:
            score = min(10.0, isc + exploitability)
        return _round_up(score)

    @staticmethod
    def severity(score: float) -> str:
        if score == 0:
            return "None"
        if score <= 3.9:
            return "Low"
        if score <= 6.9:
            return "Medium"
        if score <= 8.9:
            return "High"
        return "Critical"

    @staticmethod
    def explain(vector: CvssVector) -> Dict[str, str]:
        """Return a human-readable explanation of each metric."""
        out: Dict[str, str] = {}
        for code, (label, vals) in _METRIC_LABELS.items():
            v = getattr(vector, code)
            out[code] = f"{label}: {vals.get(v, v)}"
        return out

    @staticmethod
    def full(vector: CvssVector) -> dict:
        score = Cvss31.base_score(vector)
        return {
            "vector": vector.to_string(),
            "base_score": score,
            "severity": Cvss31.severity(score),
            "metrics": Cvss31.explain(vector),
        }


def _round_up(score: float) -> float:
    """CVSS round-up: round to one decimal, always round up if any nonzero tail."""
    # Spec: round up to nearest 0.1
    int_input = round(score * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input - int_input % 10000 + 10000) / 100000.0
