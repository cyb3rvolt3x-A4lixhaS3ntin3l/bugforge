"""Authenticated session manager for Gungnir.

Captures, stores, and replays authenticated sessions (cookies + custom auth
headers) so security tests can target authenticated endpoints. Only the
resulting session artifacts are persisted; raw credentials (usernames,
passwords) are never stored.

Session state is written to ``~/.gungnir/sessions.json`` with restrictive
``0o600`` permissions so only the owning user can read it.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..utils.logger import get_logger

logger = get_logger()

# Where sessions are persisted on disk. Kept module-level so it can be
# overridden (e.g. for tests) without monkeypatching.
SESSIONS_DIR = os.path.join(os.path.expanduser("~"), ".gungnir")
SESSIONS_FILE = os.path.join(SESSIONS_DIR, "sessions.json")

# Roles are advisory labels describing how privileged a captured session is.
VALID_ROLES = {
    "unauthenticated",
    "authenticated_user",
    "privileged_user",
    "custom",
}


def _mask(value: str) -> str:
    """Mask a sensitive value for safe logging.

    Shows the first 4 characters (or fewer, if the value is shorter) followed
    by an ellipsis. Empty values are returned as-is so logs remain honest
    about "no value present" without leaking anything.
    """
    if not value:
        return ""
    if len(value) <= 4:
        return value[:1] + "..."
    return value[:4] + "..."


@dataclass
class AuthContext:
    """A captured authenticated session.

    Attributes:
        name: Human-friendly identifier for this context (e.g. ``"admin"``).
        role: Privilege class — one of :data:`VALID_ROLES`.
        cookies: Mapping of cookie name to cookie value. Treated as sensitive.
        headers: Extra auth headers (e.g. ``Authorization``) to replay.
        created_at: Unix timestamp when the context was first created.
        last_used: Unix timestamp updated each time the context is replayed.
    """

    name: str
    role: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"AuthContext(name={self.name!r}, role={self.role!r}, "
            f"cookies={len(self.cookies)} item(s), "
            f"headers={len(self.headers)} item(s))"
        )


class SessionManager:
    """Create, store, and replay authenticated sessions.

    The manager keeps an in-memory registry of :class:`AuthContext` objects
    keyed by name. Call :meth:`save` to persist the registry to disk and
    :meth:`load` to restore it. Cookie/header *values* are sensitive and are
    masked whenever they would otherwise be logged.
    """

    def __init__(self, sessions_file: Optional[str] = None) -> None:
        # Allow callers (and tests) to point at an alternate path.
        self.sessions_file = sessions_file or SESSIONS_FILE
        self._contexts: Dict[str, AuthContext] = {}

    # ------------------------------------------------------------------ #
    # CRUD
    # ------------------------------------------------------------------ #
    def add_context(
        self,
        name: str,
        role: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> AuthContext:
        """Register a new auth context and return it.

        Replaces any existing context with the same ``name``.
        """
        if not name:
            raise ValueError("context name must be a non-empty string")
        if role not in VALID_ROLES:
            raise ValueError(
                f"invalid role {role!r}; expected one of {sorted(VALID_ROLES)}"
            )

        now = time.time()
        ctx = AuthContext(
            name=name,
            role=role,
            cookies=dict(cookies or {}),
            headers=dict(headers or {}),
            created_at=now,
            last_used=now,
        )
        self._contexts[name] = ctx
        logger.info(
            "Added auth context %r (role=%s, cookies=%d, headers=%d)",
            name,
            role,
            len(ctx.cookies),
            len(ctx.headers),
        )
        return ctx

    def get_context(self, name: str) -> Optional[AuthContext]:
        """Retrieve a context by name, or ``None`` if it does not exist."""
        ctx = self._contexts.get(name)
        if ctx is not None:
            ctx.last_used = time.time()
        return ctx

    def list_contexts(self) -> List[AuthContext]:
        """Return all registered contexts (order is insertion order)."""
        return list(self._contexts.values())

    def delete_context(self, name: str) -> bool:
        """Delete a context by name. Returns ``True`` if something was removed."""
        if name in self._contexts:
            del self._contexts[name]
            logger.info("Deleted auth context %r", name)
            return True
        logger.debug("Delete requested for unknown context %r", name)
        return False

    # ------------------------------------------------------------------ #
    # Capture
    # ------------------------------------------------------------------ #
    def capture_from_url(
        self,
        url: str,
        login_url: str,
        username: str,
        password: str,
        name: Optional[str] = None,
        role: str = "authenticated_user",
    ) -> AuthContext:
        """POST credentials to ``login_url`` and capture the session cookies.

        A very small, dependency-free login flow: the supplied username and
        password are form-encoded (fields ``username`` and ``password``) and
        POSTed to ``login_url``. Any ``Set-Cookie`` headers in the response are
        parsed and stored on a new auth context named after ``name`` (defaulting
        to ``"user"``). Raw credentials are intentionally *not* persisted — only
        the resulting cookies/headers survive.

        Note: this is a best-effort, stdlib-only capture. Forms that require a
        CSRF token, multi-step login, or JavaScript execution will need a
        richer capture mechanism; this method is intentionally basic.
        """
        ctx_name = name or "user"
        login_form = urllib.parse.urlencode(
            {"username": username, "password": password}
        ).encode("utf-8")

        req = urllib.request.Request(
            login_url,
            data=login_form,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Gungnir-SessionCapture/1.0",
            },
        )

        cookies: Dict[str, str] = {}
        headers: Dict[str, str] = {}

        try:
            # We do not follow redirects automatically here so we can inspect
            # every Set-Cookie header across the redirect chain. A cookiejar
            # collects them for us.
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(jar)
            )
            opener.open(req, timeout=15)
            for cookie in jar:
                cookies[cookie.name] = cookie.value
        except urllib.error.HTTPError as exc:
            # A non-2xx may still set cookies (e.g. login failed but session
            # issued). Capture what we can, then warn.
            logger.warning(
                "Login POST to %s returned HTTP %s; captured %d cookie(s)",
                login_url,
                exc.code,
                len(cookies),
            )
        except urllib.error.URLError as exc:
            logger.error("Failed to reach login URL %s: %s", login_url, exc.reason)
            raise

        # Replay any Authorization header the caller might want by default:
        # none here — values come only from the response.

        logger.info(
            "Captured session for %r from %s (%d cookie(s))",
            ctx_name,
            login_url,
            len(cookies),
        )
        # Log cookie *names* but mask their values.
        for cname in cookies:
            logger.debug("  cookie %s=%s", cname, _mask(cookies[cname]))

        ctx = self.add_context(
            name=ctx_name, role=role, cookies=cookies, headers=headers
        )
        # Stash the originating URL for reference without exposing creds.
        ctx.headers.setdefault("X-Gungnir-Login-URL", login_url)
        return ctx

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #
    def to_dict(self, context: AuthContext) -> dict:
        """Serialize a single context to a plain dict."""
        return {
            "name": context.name,
            "role": context.role,
            "cookies": dict(context.cookies),
            "headers": dict(context.headers),
            "created_at": context.created_at,
            "last_used": context.last_used,
        }

    def from_dict(self, data: dict) -> AuthContext:
        """Reconstruct an :class:`AuthContext` from a dict."""
        return AuthContext(
            name=data["name"],
            role=data["role"],
            cookies=dict(data.get("cookies") or {}),
            headers=dict(data.get("headers") or {}),
            created_at=float(data.get("created_at", time.time())),
            last_used=float(data.get("last_used", time.time())),
        )

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def save(self) -> str:
        """Persist all contexts to disk with ``0o600`` permissions.

        Returns the path that was written.
        """
        directory = os.path.dirname(self.sessions_file) or "."
        os.makedirs(directory, exist_ok=True)

        payload = {
            "version": 1,
            "contexts": [self.to_dict(c) for c in self._contexts.values()],
        }
        blob = json.dumps(payload, indent=2, sort_keys=True)

        # Write atomically: temp file then rename, then lock down permissions.
        tmp_path = self.sessions_file + ".tmp"
        # Create the temp file with restrictive perms from the start.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp_path, self.sessions_file)
        # Re-assert perms in case the file already existed with looser bits.
        os.chmod(self.sessions_file, 0o600)

        logger.info(
            "Saved %d auth context(s) to %s (mode 0600)",
            len(self._contexts),
            self.sessions_file,
        )
        return self.sessions_file

    def load(self) -> List[AuthContext]:
        """Load contexts from disk, replacing any in-memory state.

        Returns the list of loaded contexts. If the file does not exist, the
        registry is left empty and an empty list is returned.
        """
        if not os.path.exists(self.sessions_file):
            logger.debug("Sessions file %s does not exist; nothing to load", self.sessions_file)
            self._contexts = {}
            return []

        # Verify perms before reading; if the file is world/group readable,
        # refuse to use it and warn loudly.
        try:
            st = os.stat(self.sessions_file)
            if st.st_mode & 0o077:
                logger.warning(
                    "Sessions file %s has permissive mode %o; refusing to load. "
                    "Fix with: chmod 600 %s",
                    self.sessions_file,
                    st.st_mode & 0o777,
                    self.sessions_file,
                )
                self._contexts = {}
                return []
        except OSError as exc:
            logger.error("Cannot stat sessions file %s: %s", self.sessions_file, exc)
            self._contexts = {}
            return []

        with open(self.sessions_file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)

        # Support both the wrapped ("version" + "contexts") shape and a bare
        # list of context dicts, for forward/backward compatibility.
        if isinstance(payload, dict):
            items = payload.get("contexts", [])
        elif isinstance(payload, list):
            items = payload
        else:
            logger.error("Malformed sessions file %s; ignoring", self.sessions_file)
            self._contexts = {}
            return []

        self._contexts = {}
        loaded: List[AuthContext] = []
        for item in items:
            try:
                ctx = self.from_dict(item)
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Skipping malformed context entry: %s", exc)
                continue
            self._contexts[ctx.name] = ctx
            loaded.append(ctx)

        logger.info("Loaded %d auth context(s) from %s", len(loaded), self.sessions_file)
        return loaded
