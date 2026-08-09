import pytest
from bugforge.reporting.cvss import Cvss31, CvssVector


def test_critical_vector():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
    v = CvssVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
    score = Cvss31.base_score(v)
    assert score == pytest.approx(9.8, abs=0.1)
    assert Cvss31.severity(score) == "Critical"


def test_high_vector():
    # AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N (typical XSS) ~ 7.1 High
    v = CvssVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="L", A="N")
    score = Cvss31.base_score(v)
    assert 6.9 <= score <= 8.9
    assert Cvss31.severity(score) == "High"


def test_scope_changed_increases_score():
    base = CvssVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
    changed = CvssVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")
    assert Cvss31.base_score(changed) >= Cvss31.base_score(base)


def test_no_impact_zero_score():
    v = CvssVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N")
    assert Cvss31.base_score(v) == 0.0
    assert Cvss31.severity(0.0) == "None"


def test_parse_and_string_roundtrip():
    s = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
    v = CvssVector.parse(s)
    assert v.AV == "N"
    assert v.S == "C"
    assert v.PR == "L"
    out = v.to_string()
    assert "AV:N" in out and "S:C" in out and "PR:L" in out


def test_explain_contains_all_metrics():
    v = CvssVector()
    expl = Cvss31.explain(v)
    assert "AV" in expl and "C" in expl and "S" in expl


def test_full_returns_dict():
    info = Cvss31.full(CvssVector())
    assert "vector" in info and "base_score" in info and "severity" in info and "metrics" in info


def test_severity_boundaries():
    assert Cvss31.severity(0) == "None"
    assert Cvss31.severity(3.0) == "Low"
    assert Cvss31.severity(5.0) == "Medium"
    assert Cvss31.severity(8.0) == "High"
    assert Cvss31.severity(9.5) == "Critical"
