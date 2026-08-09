import pytest
from unittest.mock import patch, MagicMock
from bugforge.recon.subdomains import SubdomainEnum, Subdomain
from bugforge.scope.validator import parse_brief


def _mock_response(text):
    r = MagicMock()
    r.text = text
    r.status = 200
    return r


def test_enumerate_from_crtsh():
    enum = SubdomainEnum()
    crt_data = '[{"name_value": "a.example.com\\n*.example.com"}]'
    with patch.object(enum.client, "get", side_effect=[
        _mock_response(crt_data),   # crt.sh
        _mock_response(""),          # hackertarget
        _mock_response(""),          # rapiddns
        _mock_response(""),          # wayback
    ]):
        results = enum.enumerate("example.com")
    names = [r.name for r in results]
    assert "a.example.com" in names


def test_enumerate_respects_scope():
    enum = SubdomainEnum()
    scope = parse_brief("in_scope:\n  - api.example.com")
    crt_data = ('[{"name_value": "api.example.com"},'
                '{"name_value": "blog.example.com"},'
                '{"name_value": "shop.example.com"}]')
    with patch.object(enum.client, "get", side_effect=[
        _mock_response(crt_data), _mock_response(""), _mock_response(""), _mock_response(""),
    ]):
        results = enum.enumerate("example.com", scope=scope)
    names = [r.name for r in results]
    assert "api.example.com" in names
    assert "blog.example.com" not in names
    assert "shop.example.com" not in names


def test_enumerate_resolve_skips_unresolvable():
    enum = SubdomainEnum()
    crt_data = '[{"name_value": "live.example.com"}]'
    with patch.object(enum.client, "get", side_effect=[
        _mock_response(crt_data), _mock_response(""), _mock_response(""), _mock_response(""),
    ]):
        with patch("bugforge.recon.subdomains.socket.gethostbyname", return_value="1.2.3.4"):
            results = enum.enumerate("example.com", resolve=True)
    assert all(r.ip is not None for r in results)
    assert results[0].ip == "1.2.3.4"


def test_dedup_across_sources():
    enum = SubdomainEnum()
    crt = '[{"name_value": "dup.example.com"}]'
    ht = "dup.example.com,1.2.3.4\nother.example.com,5.6.7.8"
    with patch.object(enum.client, "get", side_effect=[
        _mock_response(crt), _mock_response(ht), _mock_response(""), _mock_response(""),
    ]):
        results = enum.enumerate("example.com")
    names = [r.name for r in results]
    assert names.count("dup.example.com") == 1
    assert "other.example.com" in names
