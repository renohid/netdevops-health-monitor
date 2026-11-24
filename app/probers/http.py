from __future__ import annotations

import socket
import time

import httpx

from app.config import TargetConfig
from app.probers import ProbeResult

_DNS_ERROR_MARKERS = (
    "name or service not known",
    "nodename nor servname provided",
    "temporary failure in name resolution",
    "getaddrinfo failed",
    "no address associated with hostname",
)


def _is_dns_error(exc: BaseException) -> bool:
    """Inspect the full exception chain and message for DNS resolution failures."""
    seen: set[int] = set()
    current: BaseException | None = exc

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, socket.gaierror):
            return True
        if any(marker in str(current).lower() for marker in _DNS_ERROR_MARKERS):
            return True
        current = current.__cause__ or current.__context__

    return False


async def probe_http(
    target: TargetConfig,
    timeout: float,
    client: httpx.AsyncClient | None = None,
) -> ProbeResult:
    """Perform an async HTTP GET health probe."""
    assert target.url is not None

    start = time.perf_counter()
    owns_client = client is None
    session = client or httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    try:
        response = await session.get(target.url, timeout=timeout)
        duration = time.perf_counter() - start
        status = response.status_code

        if 200 <= status < 400:
            return ProbeResult(
                target=target.name,
                check_type="http",
                success=True,
                duration_seconds=duration,
                details={"status_code": status, "url": str(response.url)},
            )

        reason = "http_5xx" if status >= 500 else "http_4xx"
        return ProbeResult(
            target=target.name,
            check_type="http",
            success=False,
            duration_seconds=duration,
            error_reason=reason,
            details={"status_code": status, "url": str(response.url)},
        )
    except httpx.TimeoutException:
        return ProbeResult(
            target=target.name,
            check_type="http",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="timeout",
        )
    except httpx.ConnectError as exc:
        return ProbeResult(
            target=target.name,
            check_type="http",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="dns_error" if _is_dns_error(exc) else "connect_error",
        )
    except httpx.HTTPError:
        return ProbeResult(
            target=target.name,
            check_type="http",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="http_error",
        )
    finally:
        if owns_client:
            await session.aclose()