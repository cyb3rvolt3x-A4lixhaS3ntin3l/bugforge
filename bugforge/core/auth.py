"""
Authentication system — bcrypt password hashing, session tokens, API keys.
Simple, secure, local. No external auth service.

Usage:
    auth = AuthManager("~/.bugforge/auth.json")
    auth.setup("researcher", "password123")     # initial setup
    if auth.verify("researcher", "password123"): # verify login
        session = auth.create_session("researcher")
        # session.token is the session cookie value
        # session.api_key is the API key for programmatic access
"""
from __future__ import annotations
import os
import json
import time
import secrets
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict
from pathlib import Path
from ..utils.logger import get_logger

log = get_logger()


@dataclass
class Session:
    token: str
    username: str
    api_key: str
    created_at: float
    expires_at: float


class AuthManager:
    """Manages authentication state — passwords, sessions, API keys."""

    def __init__(self, auth_file: str):
        self.auth_file = Path(auth_file)
        self.auth_file.parent.mkdir(parents=True, exist_ok=True)
        self._users: Dict[str, str] = {}  # username → bcrypt hash
        self._sessions: Dict[str, Session] = {}  # token → Session
        self._api_keys: Dict[str, str] = {}  # api_key → username
        self._failed_attempts: Dict[str, list] = {}  # username → [timestamps]
        self._load()

    def _load(self):
        """Load auth state from file."""
        if self.auth_file.exists():
            try:
                with open(self.auth_file, "r") as f:
                    data = json.load(f)
                    self._users = data.get("users", {})
                    self._api_keys = data.get("api_keys", {})
            except Exception as e:
                log.error(f"Failed to load auth file: {e}")

    def _save(self):
        """Save auth state to file."""
        data = {"users": self._users, "api_keys": self._api_keys}
        # Write atomically
        tmp = str(self.auth_file) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.rename(tmp, str(self.auth_file))
        # Restrict permissions
        os.chmod(self.auth_file, 0o600)

    def is_configured(self) -> bool:
        """Check if auth has been set up (at least one user exists)."""
        return len(self._users) > 0

    def setup(self, username: str, password: str) -> bool:
        """Initial setup — create the first user."""
        if self.is_configured():
            log.warning("Auth already configured. Use change_password() to change.")
            return False
        return self.add_user(username, password)

    def add_user(self, username: str, password: str) -> bool:
        """Add a new user."""
        if username in self._users:
            return False
        if len(password) < 6:
            return False
        self._users[username] = self._hash_password(password)
        self._save()
        log.info(f"User '{username}' created")
        return True

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change a user's password."""
        if username not in self._users:
            return False
        if not self.verify(username, old_password):
            return False
        if len(new_password) < 6:
            return False
        self._users[username] = self._hash_password(new_password)
        # Invalidate all sessions for this user
        to_remove = [t for t, s in self._sessions.items() if s.username == username]
        for t in to_remove:
            del self._sessions[t]
        self._save()
        return True

    def verify(self, username: str, password: str) -> bool:
        """Verify a username/password combo."""
        if username not in self._users:
            return False

        # Rate limiting: 5 failed attempts per minute
        now = time.time()
        attempts = self._failed_attempts.get(username, [])
        attempts = [t for t in attempts if now - t < 60]
        if len(attempts) >= 5:
            log.warning(f"Rate limited: too many failed attempts for '{username}'")
            return False

        if not self._check_password(password, self._users[username]):
            attempts.append(now)
            self._failed_attempts[username] = attempts
            return False

        # Clear failed attempts on success
        self._failed_attempts.pop(username, None)
        return True

    def create_session(self, username: str) -> Session:
        """Create a new session for a user."""
        token = secrets.token_hex(32)
        api_key = secrets.token_hex(32)
        now = time.time()
        session = Session(
            token=token,
            username=username,
            api_key=api_key,
            created_at=now,
            expires_at=now + 86400,  # 24 hours
        )
        self._sessions[token] = session
        self._api_keys[api_key] = username
        self._save()
        return session

    def verify_session(self, token: str) -> Optional[Session]:
        """Verify a session token. Returns the session if valid."""
        session = self._sessions.get(token)
        if not session:
            return None
        if time.time() > session.expires_at:
            del self._sessions[token]
            return None
        return session

    def verify_api_key(self, api_key: str) -> Optional[str]:
        """Verify an API key. Returns the username if valid."""
        return self._api_keys.get(api_key)

    def logout(self, token: str) -> bool:
        """Destroy a session."""
        if token in self._sessions:
            session = self._sessions[token]
            # Also remove the API key
            if session.api_key in self._api_keys:
                del self._api_keys[session.api_key]
            del self._sessions[token]
            self._save()
            return True
        return False

    def cleanup_sessions(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [t for t, s in self._sessions.items() if now > s.expires_at]
        for t in expired:
            del self._sessions[t]

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        import bcrypt
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt).decode()

    @staticmethod
    def _check_password(password: str, hashed: str) -> bool:
        """Check a password against a bcrypt hash."""
        import bcrypt
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False
