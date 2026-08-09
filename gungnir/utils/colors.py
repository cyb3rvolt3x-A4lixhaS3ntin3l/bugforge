"""Minimal ANSI color helpers — no third-party dependency."""


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GREY = "\033[90m"


def c(text: str, color: str) -> str:
    """Wrap ``text`` in an ANSI color code."""
    return f"{color}{text}{Colors.RESET}"
