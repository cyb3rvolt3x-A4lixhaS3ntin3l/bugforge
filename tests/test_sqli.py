from bugforge.vulns.sqli import SqliHelper
from unittest.mock import patch, MagicMock


def test_fingerprint_mysql_error():
    helper = SqliHelper()
    body = ("You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax")
    errors = helper.fingerprint_errors(body)
    assert any(e.database == "mysql" for e in errors)


def test_fingerprint_postgres_error():
    helper = SqliHelper()
    body = "PostgreSQL ERROR: syntax error at or near \"x\""
    errors = helper.fingerprint_errors(body)
    assert any(e.database == "postgresql" for e in errors)


def test_fingerprint_oracle_error():
    helper = SqliHelper()
    body = "ORA-01756: quoted string not properly terminated"
    errors = helper.fingerprint_errors(body)
    assert any(e.database == "oracle" for e in errors)


def test_fingerprint_clean_body():
    helper = SqliHelper()
    assert helper.fingerprint_errors("just normal content") == []


def test_boolean_payloads_returned():
    helper = SqliHelper()
    pairs = helper.boolean_payloads()
    assert len(pairs) > 0
    assert all(len(p) == 2 for p in pairs)


def test_time_payloads_returned():
    helper = SqliHelper()
    tps = helper.time_payloads()
    assert len(tps) > 0
    dbs = [db for db, _ in tps]
    assert "mysql" in dbs and "postgresql" in dbs
