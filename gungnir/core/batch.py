"""
Multi-target batch scanner.

Runs the full Gungnir scan against several targets concurrently with a
bounded semaphore (max 3 in flight by default) and returns a mapping of
target → ScanResult. Progress callbacks fire per-target.

Stdlib + asyncio only. The per-target scan is delegated to the existing
ParallelEngine.full_scan coroutine in gungnir.core.parallel, which is
the same path the CLI uses for a single hunt.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Dict, List, Optional

from .detect import TargetType, detect_target_type
from .parallel import ParallelEngine, ScanResult
from ..utils.logger import get_logger

log = get_logger()

# Hard cap on concurrent scans — more than this thrashes the host
# (subprocess fan-out inside each scan is already parallel).
DEFAULT_MAX_CONCURRENT = 3

# Progress callback shape: async (target, tool_name, message) -> None
ProgressCb = Optional[Callable[[str, str, str], Awaitable[None]]]


async def _scan_one(
    target: str,
    options: Dict,
    engine: ParallelEngine,
    semaphore: asyncio.Semaphore,
    progress_cb: ProgressCb,
) -> ScanResult:
    """Scan a single target under the shared semaphore."""
    async with semaphore:
        if progress_cb:
            try:
                await progress_cb(target, "scan", "starting")
            except Exception:  # progress cb must never break the scan
                pass

        target_type = detect_target_type(target)
        try:
            result = await engine.full_scan(
                target,
                target_type,
                options=options,
            )
        except Exception as exc:
            log.error("batch_scan: target %s failed: %s", target, exc)
            result = ScanResult(target=target, target_type=target_type)

        if progress_cb:
            try:
                n = len(result.all_findings)
                await progress_cb(target, "scan", f"done ({n} findings)")
            except Exception:
                pass

        return result


async def batch_scan_async(
    targets: List[str],
    options: Optional[Dict] = None,
    progress_cb: ProgressCb = None,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    engine: Optional[ParallelEngine] = None,
) -> Dict[str, ScanResult]:
    """
    Run scans for multiple targets concurrently.

    Args:
        targets:        list of target strings (domains/IPs/URLs).
        options:        per-scan options dict forwarded to full_scan.
        progress_cb:    async callback (target, tool, message) -> None.
        max_concurrent: max simultaneous scans (default 3).
        engine:         existing ParallelEngine to reuse; one is built if None.

    Returns:
        dict mapping target string → ScanResult. Targets that errored are
        present with an (mostly) empty ScanResult so callers can iterate
        uniformly.
    """
    options = options or {}
    semaphore = asyncio.Semaphore(max(1, max_concurrent))

    owns_engine = engine is None
    if engine is None:
        from .binaries import BinaryManager
        from .config import get_config
        cfg = get_config()
        engine = ParallelEngine(BinaryManager(str(cfg.bin_dir)),
                                max_concurrent=cfg.max_concurrent)

    tasks = [
        _scan_one(t, options, engine, semaphore, progress_cb)
        for t in targets
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    out: Dict[str, ScanResult] = {}
    for target, res in zip(targets, results):
        if isinstance(res, Exception):
            log.error("batch_scan: %s raised: %s", target, res)
            out[target] = ScanResult(target=target,
                                     target_type=detect_target_type(target))
        else:
            out[target] = res

    if owns_engine:
        # nothing to explicitly close today, but keep the seam for future
        # resource cleanup.
        pass

    return out


def batch_scan(
    targets: List[str],
    options: Optional[Dict] = None,
    progress_cb: ProgressCb = None,
) -> Dict[str, ScanResult]:
    """
    Synchronous wrapper around batch_scan_async.

    Runs the batch scan in a fresh event loop and returns a dict of
    target → ScanResult. Suitable for CLI/script entry points.

    Args:
        targets:     list of target strings.
        options:     per-scan options dict forwarded to full_scan.
        progress_cb: async callback (target, tool, message) -> None.

    Returns:
        dict mapping target → ScanResult.
    """
    if not targets:
        return {}

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(
            batch_scan_async(targets, options=options, progress_cb=progress_cb)
        )
    finally:
        try:
            loop.close()
        except Exception:
            pass
        asyncio.set_event_loop(None)
