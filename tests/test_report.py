import pytest
from gungnir.reporting.report import ReportBuilder, ReportTemplate


def test_xss_template_builds_markdown():
    t = ReportBuilder.xss_template("https://app.example.com/search?q=test",
                                    "<script>alert(1)</script>", reporter="hunter")
    md = ReportBuilder(t).build()
    assert "# Reflected Cross-Site Scripting" in md
    assert "CVSS:3.1" in md
    assert "<script>alert(1)</script>" in md
    assert "hunter" in md
    assert "## Steps to Reproduce" in md
    assert "## Impact" in md


def test_idor_template():
    t = ReportBuilder.idor_template("https://app.example.com/api/users/42", "42")
    md = ReportBuilder(t).build()
    assert "IDOR" in md
    assert "/api/users/42" in md


def test_ssrf_template_critical():
    t = ReportBuilder.ssrf_template("https://app.example.com/fetch", "http://169.254.169.254/latest/meta-data/")
    md = ReportBuilder(t).build()
    assert "Critical" in md
    assert "SSRF" in md
    assert "169.254.169.254" in md


def test_secret_template():
    t = ReportBuilder.secret_template("https://app.example.com/config", "AWS Key", "AKIA****")
    md = ReportBuilder(t).build()
    assert "Sensitive Data" in md or "Secret" in md


def test_report_includes_references():
    t = ReportBuilder.ssrf_template("https://x.com", "http://169.254.169.254/")
    md = ReportBuilder(t).build()
    assert "## References" in md
    assert "owasp.org" in md


def test_report_custom_template():
    t = ReportTemplate(
        title="Custom Bug", severity="Medium",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        summary="A custom finding.", affected_url="https://app.example.com/x",
        steps=["step one", "step two"], poc="curl https://app.example.com",
    )
    md = ReportBuilder(t).build()
    assert "Custom Bug" in md
    assert "step one" in md
    assert "curl https://app.example.com" in md


def test_report_severity_and_score_rendered():
    t = ReportBuilder.idor_template("https://app.example.com/api/users/1", "1")
    md = ReportBuilder(t).build()
    assert "High" in md
