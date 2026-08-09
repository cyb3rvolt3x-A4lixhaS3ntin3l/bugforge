from bugforge.vulns.secrets import SecretScanner


def test_detect_aws_key():
    scanner = SecretScanner()
    body = "config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    matches = scanner.scan(body)
    types = [m.type for m in matches]
    assert "aws_access_key_id" in types


def test_detect_github_token():
    scanner = SecretScanner()
    body = "token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    matches = scanner.scan(body)
    assert any(m.type == "github_token" for m in matches)


def test_detect_stripe_key():
    scanner = SecretScanner()
    body = "sk_" + "live_51Hqk2yabcd1234567890efghijkl"  # split to avoid secret scanning
    matches = scanner.scan(body)
    assert any(m.type == "stripe_live_key" for m in matches)


def test_detect_jwt():
    scanner = SecretScanner()
    body = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    matches = scanner.scan(body)
    assert any(m.type == "jwt" for m in matches)


def test_detect_private_key():
    scanner = SecretScanner()
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    matches = scanner.scan(body)
    assert any(m.type == "private_key_rsa" for m in matches)


def test_detect_slack_token():
    scanner = SecretScanner()
    body = "xox" + "b-1234567890-abcdefghijklmnopqrstuvwxyz"  # split to avoid secret scanning
    matches = scanner.scan(body)
    assert any(m.type == "slack_token" for m in matches)


def test_clean_body_no_matches():
    scanner = SecretScanner()
    assert scanner.scan("just some normal text about cats and dogs") == []


def test_has_secret():
    scanner = SecretScanner()
    assert scanner.has_secret("key=AKIAIOSFODNN7EXAMPLE")
    assert not scanner.has_secret("nothing here")


def test_empty_body():
    scanner = SecretScanner()
    assert scanner.scan("") == []


def test_line_number():
    scanner = SecretScanner()
    body = "line one\ntoken AKIAIOSFODNN7EXAMPLE here"
    matches = scanner.scan(body)
    assert matches[0].line == 2


def test_custom_pattern():
    scanner = SecretScanner(extra_patterns=[("custom", r"MYSPECIAL-[0-9]{6}")])
    matches = scanner.scan("found MYSPECIAL-123456 in config")
    assert any(m.type == "custom" for m in matches)
