from bugforge.vulns.cors import CorsChecker, CorsResult
from bugforge.utils.http import HttpResponse
from unittest.mock import patch


def _resp(headers):
    return HttpResponse(url="https://api.example.com/data", status=200, headers=headers, body=b"")


def test_reflected_origin_with_credentials_vulnerable():
    checker = CorsChecker()
    # returns ACAO reflecting the evil origin + ACAC true
    def fake_get(url, headers=None):
        origin = headers.get("Origin") if headers else None
        return _resp({"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
    with patch.object(checker.client, "get", side_effect=fake_get):
        results = checker.check("https://api.example.com/data")
    assert any(r.vulnerable for r in results)


def test_wildcard_no_creds_not_exploitable():
    checker = CorsChecker()
    with patch.object(checker.client, "get", return_value=_resp({"Access-Control-Allow-Origin": "*"})):
        results = checker.check("https://api.example.com/data")
    assert all(not r.vulnerable for r in results)


def test_null_origin_with_creds_vulnerable():
    checker = CorsChecker()
    def fake_get(url, headers=None):
        origin = headers.get("Origin")
        if origin == "null":
            return _resp({"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"})
        return _resp({})
    with patch.object(checker.client, "get", side_effect=fake_get):
        results = checker.check("https://api.example.com/data")
    null_result = [r for r in results if r.origin == "null"][0]
    assert null_result.vulnerable


def test_no_acao_not_vulnerable():
    checker = CorsChecker()
    with patch.object(checker.client, "get", return_value=_resp({})):
        results = checker.check("https://api.example.com/data")
    assert all(not r.vulnerable for r in results)
