"""
API discovery — finds GraphQL, REST, Swagger/OpenAPI, and SOAP endpoints.
No external tool dependency — pure Python.
"""
from __future__ import annotations
import json
import re
import urllib.request
from typing import List
from ..utils.logger import get_logger

log = get_logger()


# Common API endpoint paths to check
API_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/swagger.json", "/swagger-ui/", "/swagger-ui.html",
    "/api-docs", "/api/docs", "/openapi.json", "/openapi.yaml",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/v1/", "/v2/", "/api/",
    "/soap", "/wsdl", "/api/soap",
    "/.well-known/openid-configuration",
    "/actuator", "/actuator/health", "/actuator/env",
    "/api/health", "/health", "/api/status",
]


def discover_apis(target: str) -> List[dict]:
    """Probe a target for API endpoints."""
    findings = []
    target = _normalize(target)

    for path in API_PATHS:
        url = f"{target.rstrip('/')}{path}"
        result = _fetch(url)

        if result["status"] == 0 or not result["body"]:
            continue

        # GraphQL detection
        if "graphql" in path.lower():
            if result["status"] == 200 and ("data" in result["body"] or "errors" in result["body"]):
                findings.append({
                    "type": "graphql_endpoint",
                    "url": url,
                    "status": result["status"],
                    "source": "api_discoverer",
                    "note": "GraphQL endpoint detected — test introspection",
                })
                # Try introspection
                intro = _graphql_introspection(url)
                if intro:
                    findings.append({
                        "type": "graphql_introspection_enabled",
                        "url": url,
                        "source": "api_discoverer",
                        "note": "GraphQL introspection is enabled — full schema exposed",
                        "schema": intro[:500],
                    })
            elif result["status"] == 405:
                findings.append({
                    "type": "graphql_endpoint",
                    "url": url,
                    "status": result["status"],
                    "source": "api_discoverer",
                    "note": "GraphQL endpoint detected (405 — try POST)",
                })

        # Swagger/OpenAPI detection
        elif "swagger" in path.lower() or "openapi" in path.lower() or "api-docs" in path.lower():
            if result["status"] == 200:
                try:
                    data = json.loads(result["body"])
                    if "swagger" in str(data) or "openapi" in str(data) or "paths" in data:
                        paths = list(data.get("paths", {}).keys())
                        findings.append({
                            "type": "swagger_exposed",
                            "url": url,
                            "source": "api_discoverer",
                            "note": f"Swagger/OpenAPI spec exposed — {len(paths)} endpoints",
                            "paths": paths[:20],
                        })
                except json.JSONDecodeError:
                    pass

        # Generic API endpoint detection
        elif result["status"] == 200 and not _is_html(result["body"]):
            if any(kw in result["body"][:200].lower() for kw in ["json", "api", "endpoint", "version"]):
                findings.append({
                    "type": "api_endpoint",
                    "url": url,
                    "status": result["status"],
                    "source": "api_discoverer",
                    "note": "API endpoint detected",
                })

        # Actuator/Spring detection
        elif "actuator" in path:
            if result["status"] == 200:
                findings.append({
                    "type": "actuator_exposed",
                    "url": url,
                    "source": "api_discoverer",
                    "note": "Spring Boot Actuator endpoint exposed — check /actuator/env for secrets",
                })

    return findings


def _graphql_introspection(url: str) -> str:
    """Try GraphQL introspection query."""
    query = json.dumps({"query": "{ __schema { types { name } } }"}).encode()
    req = urllib.request.Request(url, data=query, headers={
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
    })
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _fetch(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    })
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"status": resp.status, "body": resp.read().decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "body": body}
    except Exception:
        return {"status": 0, "body": ""}


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _is_html(body: str) -> bool:
    return body.strip().startswith(("<!", "<html", "<HTML")) or "<body" in body[:500].lower()
