from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any

from app.config import TargetConfig
from app.probers import ProbeResult
from app.probers.tcp import _safe_close


def _extract_issuer(peercert: dict[str, Any]) -> str:
    """Extract Common Name (or Organization fallback) from a decoded peer certificate."""
    issuer_rdns = peercert.get("issuer", ())
    fields: dict[str, str] = {}
    for rdn in issuer_rdns:
        for key, value in rdn:
            fields[key] = value
    return fields.get("commonName") or fields.get("organizationName") or "unknown"


async def probe_tls(target: TargetConfig, timeout: float) -> ProbeResult:
    """Perform a TLS handshake and inspect peer certificate expiration and issuer."""
    assert target.host is not None and target.port is not None

    start = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    ssl_context = ssl.create_default_context()

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=target.host,
                port=target.port,
                ssl=ssl_context,
                server_hostname=target.host,
            ),
            timeout=timeout,
        )
        duration = time.perf_counter() - start

        peercert: dict[str, Any] | None = writer.get_extra_info("peercert")
        if not peercert or "notAfter" not in peercert:
            return ProbeResult(
                target=target.name,
                check_type="tls",
                success=False,
                duration_seconds=duration,
                error_reason="missing_cert",
            )

        expiry_timestamp = ssl.cert_time_to_seconds(peercert["notAfter"])
        now_timestamp = datetime.now(UTC).timestamp()
        days_remaining = round((expiry_timestamp - now_timestamp) / 86400.0, 2)
        issuer = _extract_issuer(peercert)

        ssl_obj = writer.get_extra_info("ssl_object")
        tls_version = ssl_obj.version() if ssl_obj and hasattr(ssl_obj, "version") else "unknown"

        is_valid = days_remaining >= 0
        return ProbeResult(
            target=target.name,
            check_type="tls",
            success=is_valid,
            duration_seconds=duration,
            error_reason=None if is_valid else "cert_expired",
            details={
                "tls_days_remaining": days_remaining,
                "tls_issuer": issuer,
                "tls_version": tls_version,
                "not_after": peercert["notAfter"],
            },
        )
    except ssl.SSLError:
        return ProbeResult(
            target=target.name,
            check_type="tls",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="ssl_error",
        )
    except TimeoutError:
        return ProbeResult(
            target=target.name,
            check_type="tls",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="timeout",
        )
    except socket.gaierror:
        return ProbeResult(
            target=target.name,
            check_type="tls",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="dns_error",
        )
    except ConnectionRefusedError:
        return ProbeResult(
            target=target.name,
            check_type="tls",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="refused",
        )
    except OSError:
        return ProbeResult(
            target=target.name,
            check_type="tls",
            success=False,
            duration_seconds=time.perf_counter() - start,
            error_reason="network_error",
        )
    finally:
        await _safe_close(writer)