"""
Bug-bounty report builder.

Generates clean, well-structured Markdown reports that maximize payout by
emphasizing clarity, reproducibility, and impact — exactly what triagers want.
Includes common report templates (XSS, IDOR, SSRF, CORS, secret exposure).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from textwrap import indent

from .cvss import Cvss31, CvssVector


@dataclass
class ReportTemplate:
    title: str
    severity: str  # None|Low|Medium|High|Critical
    cvss_vector: str  # CVSS:3.1/...
    summary: str
    affected_url: str
    steps: List[str] = field(default_factory=list)
    impact: str = ""
    poc: str = ""           # proof-of-concept (curl, request, etc.)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    reporter: str = ""
    program: str = ""


class ReportBuilder:
    """Build a Markdown bug report from structured fields."""

    def __init__(self, template: ReportTemplate):
        self.t = template

    def build(self) -> str:
        t = self.t
        cvss = CvssVector.parse(t.cvss_vector)
        score_info = Cvss31.full(cvss)

        lines: List[str] = []
        lines.append(f"# {t.title}")
        lines.append("")
        if t.reporter:
            lines.append(f"**Reporter:** {t.reporter}  ")
        if t.program:
            lines.append(f"**Program:** {t.program}  ")
        lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}  ")
        lines.append(f"**Severity:** {t.severity} ({score_info['base_score']})  ")
        lines.append(f"**CVSS:** `{score_info['vector']}`  ")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(t.summary)
        lines.append("")
        lines.append("## Affected Asset")
        lines.append("")
        lines.append(f"`{t.affected_url}`")
        lines.append("")
        lines.append("## Vulnerability Description")
        lines.append("")
        lines.append(self._description())
        lines.append("")
        lines.append("## Steps to Reproduce")
        lines.append("")
        for i, step in enumerate(t.steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        if t.poc:
            lines.append("## Proof of Concept")
            lines.append("")
            lines.append("```")
            lines.append(t.poc.strip())
            lines.append("```")
            lines.append("")
        lines.append("## Impact")
        lines.append("")
        lines.append(t.impact or self._default_impact())
        lines.append("")
        lines.append("## Remediation")
        lines.append("")
        lines.append(t.remediation or self._default_remediation())
        lines.append("")
        if t.references:
            lines.append("## References")
            lines.append("")
            for r in t.references:
                lines.append(f"- {r}")
            lines.append("")
        lines.append("---")
        lines.append("*Generated with [Gungnir](https://github.com/) — bug bounty toolkit.*")
        lines.append("")
        return "\n".join(lines)

    def _description(self) -> str:
        return (f"This report details a {self.t.severity}-severity {self._vuln_name()} "
                f"vulnerability affecting `{self.t.affected_url}`.")

    def _vuln_name(self) -> str:
        title = self.t.title.lower()
        for name in ["cross-site scripting", "xss", "idor", "ssrf", "cors",
                     "sql injection", "sensitive data", "secret"]:
            if name in title:
                return name.upper()
        return "security"

    def _default_impact(self) -> str:
        return ("An attacker exploiting this issue could compromise the confidentiality, "
                "integrity, or availability of affected user data. See steps above for "
                "a concrete demonstration of impact.")

    def _default_remediation(self) -> str:
        return ("Validate and sanitize all user input on both client and server side. "
                "Enforce authorization checks on every object access. Apply the principle "
                "of least privilege. Add automated tests covering this attack path.")

    # ---- convenience templates ----

    @staticmethod
    def xss_template(url: str, payload: str, reporter: str = "") -> ReportTemplate:
        return ReportTemplate(
            title="Reflected Cross-Site Scripting (XSS)",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
            summary=("A reflected XSS vulnerability exists in a parameter of the "
                     "affected endpoint. User input is reflected into the response "
                     "without sufficient output encoding, allowing script execution "
                     "in a victim's browser."),
            affected_url=url,
            steps=[
                f"Navigate to `{url}`",
                f"Inject the payload `{payload}` into the vulnerable parameter",
                "Observe the payload executes in the browser context (alert fires)",
                "Craft a malicious link to trigger execution in a victim session",
            ],
            poc=f"GET {url}\n\nPayload: {payload}",
            impact=("Session hijacking, cookie theft, account takeover, "
                   "defacement, and phishing of legitimate users."),
            remediation=("Apply context-aware output encoding (HTML, JS, URL) to "
                         "all reflected user input. Use a strict Content Security "
                         "Policy. Consider a mature templating engine with auto-escaping."),
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
            reporter=reporter,
        )

    @staticmethod
    def idor_template(url: str, object_id: str, reporter: str = "") -> ReportTemplate:
        return ReportTemplate(
            title="Insecure Direct Object Reference (IDOR)",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            summary=("An IDOR vulnerability allows an authenticated user to access "
                     "another user's resources by manipulating object identifiers. "
                     "Authorization is not enforced server-side on the requested object."),
            affected_url=url,
            steps=[
                f"Authenticate as a low-privilege user",
                f"Request `{url}` (object id `{object_id}` belongs to another user)",
                "Observe the server returns the other user's data (HTTP 200)",
                "Iterate object IDs to enumerate further resources",
            ],
            impact=("Unauthorized access to other users' private data, potential "
                    "mass data extraction, and account-takeover-adjacent impacts."),
            remediation=("Enforce per-object authorization checks server-side. "
                         "Use indirect references or capability tokens. "
                         "Never rely on obscurity of object IDs."),
            reporter=reporter,
        )

    @staticmethod
    def ssrf_template(url: str, metadata_endpoint: str, reporter: str = "") -> ReportTemplate:
        return ReportTemplate(
            title="Server-Side Request Forgery (SSRF)",
            severity="Critical",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            summary=("An SSRF vulnerability allows an attacker to coerce the server "
                     "into making arbitrary requests, including to internal services "
                     "and cloud metadata endpoints."),
            affected_url=url,
            steps=[
                f"Identify the URL-fetching parameter at `{url}`",
                f"Replace it with `{metadata_endpoint}`",
                "Observe the response contains internal metadata/credentials",
                "Confirm via an out-of-band callback host",
            ],
            impact=("Cloud credential theft, internal network pivoting, access to "
                    "internal-only services, and potential full account compromise."),
            remediation=("Validate and allow-list outbound destinations. Block "
                         "link-local (169.254.0.0/16), loopback, and private ranges. "
                         "Disable HTTP redirects or re-validate after redirect. "
                         "Use a network namespace/egress firewall for fetch workers."),
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf",
            ],
            reporter=reporter,
        )

    @staticmethod
    def secret_template(url: str, secret_type: str, value_hint: str, reporter: str = "") -> ReportTemplate:
        return ReportTemplate(
            title="Sensitive Data Exposure — Leaked Secret",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            summary=("A sensitive secret (API key / token) is exposed in a public "
                     "response, allowing unauthorized access to the associated service."),
            affected_url=url,
            steps=[
                f"Access `{url}`",
                f"Inspect the response; observe an exposed {secret_type}",
                f"Secret sample (masked): {value_hint}",
            ],
            impact=("Direct access to the associated third-party service, potential "
                    "data exfiltration, billing abuse, and lateral movement."),
            remediation=("Never embed secrets in client-accessible responses. "
                         "Store secrets in a vault and inject at runtime server-side. "
                         "Rotate the exposed credential immediately."),
            reporter=reporter,
        )
