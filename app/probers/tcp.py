from __future__ import annotations

import asyncio
import inspect
import socket
import time

from app.config import TargetConfig
from app.probers import ProbeResult


async def _safe_close(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    wait_closed = getattr(writer, "wait_closed", None)
    if callable(wait_closed):
        result = wait_closed()
        if inspect.isawaitable(result):
            await result


async def probe_tcp(target: TargetConfig, timeout: float) -> ProbeResult:
    """Perform a non-blocking TCP three-way handshake probe."""
    assert target.host is not None and target.port is not None

    start = time.perf_counter()
    writer: asyncio.StreamWriter | None = None

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host=target.host, port=target.port),
            timeout=timeout,
        )
        duration = time.perf_counter() - start
        return ProbeResult(
            target=target.name,
            check_type="tcp",
            success=True,
            duration_seconds=duration,
            details={"host": target.host, "port": target.port},
        )
    except TimeoutError:
        return ProbeResult(
            target=target.name,
            check_type="tcp",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="timeout",
        )
    except socket.gaierror:
        return ProbeResult(
            target=target.name,
            check_type="tcp",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="dns_error",
        )
    except ConnectionRefusedError:
        return ProbeResult(
            target=target.name,
            check_type="tcp",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="refused",
        )
    except OSError:
        return ProbeResult(
            target=target.name,
            check_type="tcp",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="network_error",
        )
    finally:
        await _safe_close(writer)