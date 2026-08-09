import pytest
from gungnir.scope.validator import parse_brief, load_brief_file, Scope, ScopeValidator, _parse_rule


def test_parse_wildcard_in_scope():
    scope = parse_brief("""
    in_scope:
      - *.example.com
    out_of_scope:
      - *.staging.example.com
    """)
    assert scope.is_in_scope("https://app.example.com/")[0] is True
    assert scope.is_in_scope("https://staging.example.com/")[0] is False
    assert scope.is_in_scope("https://other.com/")[0] is False


def test_wildcard_matches_apex():
    scope = parse_brief("in_scope:\n  - *.example.com")
    # *.example.com should match example.com too (per common brief convention)
    assert scope.is_in_scope("https://example.com/")[0] is True
    assert scope.is_in_scope("https://sub.example.com/")[0] is True


def test_out_of_scope_precedence():
    scope = parse_brief("""
    in_scope:
      - *.example.com
    out_of_scope:
      - admin.example.com
    """)
    ok, reason = scope.is_in_scope("https://admin.example.com/")
    assert ok is False
    assert "out-of-scope" in reason


def test_json_brief():
    scope = parse_brief('{"in_scope": ["api.example.com"], "out_of_scope": ["dev.api.example.com"]}')
    assert scope.is_in_scope("https://api.example.com/")[0] is True
    assert scope.is_in_scope("https://dev.api.example.com/")[0] is False


def test_ip_in_scope():
    scope = parse_brief("in_scope:\n  - 10.0.0.0/24")
    assert scope.is_in_scope("https://10.0.0.5/")[0] is True
    assert scope.is_in_scope("https://10.0.1.5/")[0] is False


def test_single_ip_rule():
    scope = parse_brief("in_scope:\n  - 192.168.1.1")
    assert scope.is_in_scope("https://192.168.1.1/")[0] is True
    assert scope.is_in_scope("https://192.168.1.2/")[0] is False


def test_host_rule():
    scope = parse_brief("in_scope:\n  - api.example.com")
    assert scope.is_in_scope("https://api.example.com/")[0] is True
    assert scope.is_in_scope("https://www.api.example.com/")[0] is False


def test_filter_in_scope():
    scope = parse_brief("in_scope:\n  - *.example.com")
    v = ScopeValidator(scope)
    targets = ["https://a.example.com/", "https://b.com/", "https://c.example.com/"]
    result = v.filter_in_scope(targets)
    assert result == ["https://a.example.com/", "https://c.example.com/"]


def test_load_brief_file(tmp_path):
    p = tmp_path / "brief.txt"
    p.write_text("in_scope:\n  - *.test.com\n")
    scope = load_brief_file(str(p))
    assert scope.is_in_scope("https://app.test.com/")[0] is True


def test_comments_ignored():
    scope = parse_brief("""
    # this is a comment
    in_scope:
      - *.example.com
    """)
    assert scope.is_in_scope("https://app.example.com/")[0] is True


def test_empty_brief():
    scope = parse_brief("")
    assert scope.is_in_scope("https://anything.com/")[0] is False
