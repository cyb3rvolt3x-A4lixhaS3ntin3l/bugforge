from bugforge.recon.fingerprint import TechFingerprinter, FingerprintResult
from bugforge.utils.http import HttpResponse
from unittest.mock import patch


def _resp(headers, body=""):
    return HttpResponse(url="https://x.com", status=200, headers=headers, body=body.encode())


def test_detect_nginx():
    fp = TechFingerprinter()
    with patch.object(fp.client, "get", return_value=_resp({"Server": "nginx/1.25.0", "X-Powered-By": "Express"})):
        res = fp.fingerprint("https://x.com")
    techs = {t.technology for t in res.technologies}
    assert "Nginx" in techs
    assert "Express.js" in techs


def test_detect_wordpress_body():
    fp = TechFingerprinter()
    body = '<html><meta name="generator" content="WordPress 6.4"><a href="/wp-content/themes/x">link</a></html>'
    with patch.object(fp.client, "get", return_value=_resp({}, body)):
        res = fp.fingerprint("https://x.com")
    techs = {t.technology for t in res.technologies}
    assert "WordPress" in techs


def test_missing_security_headers():
    fp = TechFingerprinter()
    headers = {"Server": "nginx"}
    missing = fp.missing_security_headers(headers)
    assert "Content-Security-Policy" in missing
    assert "Strict-Transport-Security" in missing


def test_missing_security_headers_complete():
    fp = TechFingerprinter()
    full = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    assert fp.missing_security_headers(full) == []
