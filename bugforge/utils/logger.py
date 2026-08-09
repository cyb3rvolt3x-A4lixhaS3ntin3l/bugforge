"""Lightweight logger with optional verbose/debug levels."""
import logging
import sys

_LOGGER = logging.getLogger("bugforge")
_HANDLER = logging.StreamHandler(sys.stderr)
_HANDLER.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
_LOGGER.addHandler(_HANDLER)
_LOGGER.setLevel(logging.INFO)

# Silence urllib3 unless verbose
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger() -> logging.Logger:
    return _LOGGER


def set_verbose(verbose: bool = False) -> None:
    _LOGGER.setLevel(logging.DEBUG if verbose else logging.INFO)
    if verbose:
        logging.getLogger("urllib3").setLevel(logging.INFO)
