"""Native analysis modules — capabilities external tools don't provide."""

from .js_analyzer import analyze_js  # noqa: F401
from .param_miner import mine_parameters  # noqa: F401
from .api_discover import discover_apis  # noqa: F401

from .header_analyzer import analyze_headers  # noqa: F401
from .subdomain_takeover import check_takeover  # noqa: F401
from .http_methods import test_methods  # noqa: F401
from .backup_finder import find_backups  # noqa: F401
from .redirect_mapper import map_redirects  # noqa: F401

__all__ = [
    # Existing modules
    "analyze_js",
    "mine_parameters",
    "discover_apis",
    # New security modules
    "analyze_headers",
    "check_takeover",
    "test_methods",
    "find_backups",
    "map_redirects",
]
