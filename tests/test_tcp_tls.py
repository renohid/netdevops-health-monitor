from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from prometheus_client import CollectorRegistry

from app.config import MonitorConfig, MonitorDefaults, TargetConfig, TargetTags
from app.metrics import MonitorMetrics
from app.probers.tcp import probe_tcp
from app.probers.tls import probe_tls
from app.scheduler import ProbeScheduler
from tests.conftest import format_cert_time


async def test_probe_tcp_success(
    mock_stream_factory: Callable[..., tuple[AsyncMock, MagicMock]],
) -> None:
    target = TargetConfig(name="edge-fw", host="10.0.0.1", port=443, checks=["tcp"])
    reader, writer = mock_stream_factory()

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))) as mock_conn:
        result = await probe_tcp(target, timeout=2.0)

    mock_conn.assert_awaited_once_with(host="10.0.0.1", port=443)
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()
    assert result.success is True
    assert result.error_reason is None
    assert result.duration_seconds >= 0


@pytest.mark.parametrize(
    ("exc", "expected_reason"),
    [
        (TimeoutError(), "timeout"),
        (socket.gaierror(-2, "Name or service not known"), "dns_error"),
        (ConnectionRefusedError(), "refused"),
        (OSError("Network is unreachable"), "network_error"),
    ],
)
async def test_probe_tcp_failure_classification(
    exc: Exception,
    expected_reason: str,
) -> None:
    target = TargetConfig(name="edge-fw", host="10.0.0.1", port=443, checks=["tcp"])

    with patch("asyncio.open_connection", new=AsyncMock(side_effect=exc)):
        result = await probe_tcp(target, timeout=1.0)

    assert result.success is False
    assert result.error_reason == expected_reason


async def test_probe_tls_valid_certificate(
    mock_stream_factory: Callable[..., tuple[AsyncMock, MagicMock]],
) -> None:
    target = TargetConfig(name="gateway-tls", host="gateway.example.com", port=443, checks=["tls"])
    cert = {
        "issuer": ((("organizationName", "Let's Encrypt"), ("commonName", "R11")),),
        "notAfter": format_cert_time(days_offset=45.0),
    }
    reader, writer = mock_stream_factory(peercert=cert, tls_version="TLSv1.3")

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
        result = await probe_tls(target, timeout=2.0)

    assert result.success is True
    assert result.error_reason is None
    assert result.details["tls_issuer"] == "R11"
    assert result.details["tls_version"] == "TLSv1.3"
    assert 44.9 <= result.details["tls_days_remaining"] <= 45.1


async def test_probe_tls_expired_certificate_reports_negative_days(
    mock_stream_factory: Callable[..., tuple[AsyncMock, MagicMock]],
) -> None:
    target = TargetConfig(name="expired-host", host="old.example.com", port=443, checks=["tls"])
    cert = {
        "issuer": ((("commonName", "Internal CA"),),),
        "notAfter": format_cert_time(days_offset=-3.0),
    }
    reader, writer = mock_stream_factory(peercert=cert)

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
        result = await probe_tls(target, timeout=2.0)

    assert result.success is False
    assert result.error_reason == "cert_expired"
    assert result.details["tls_days_remaining"] < 0


async def test_probe_tls_ssl_handshake_error() -> None:
    target = TargetConfig(name="bad-tls", host="bad.example.com", port=443, checks=["tls"])

    with patch(
        "asyncio.open_connection",
        new=AsyncMock(side_effect=ssl.SSLCertVerificationError("certificate verify failed")),
    ):
        result = await probe_tls(target, timeout=2.0)

    assert result.success is False
    assert result.error_reason == "ssl_error"


async def test_scheduler_fault_isolation_and_metric_updates(
    isolated_registry: CollectorRegistry,
    metrics: MonitorMetrics,
    mock_stream_factory: Callable[..., tuple[AsyncMock, MagicMock]],
) -> None:
    """One timed-out target must not prevent healthy targets from updating Prometheus metrics."""
    healthy_target = TargetConfig(
        name="healthy-edge",
        host="10.0.1.10",
        port=443,
        checks=["tls"],
        tags=TargetTags(site="dc-1", role="edge"),
    )
    failing_target = TargetConfig(
        name="dead-edge",
        host="10.0.1.99",
        port=443,
        checks=["tls"],
        tags=TargetTags(site="dc-2", role="edge"),
    )
    cfg = MonitorConfig(
        defaults=MonitorDefaults(interval_seconds=10.0, timeout_seconds=1.0),
        targets=[healthy_target, failing_target],
    )

    cert = {
        "issuer": ((("commonName", "DigiCert"),),),
        "notAfter": format_cert_time(days_offset=30.0),
    }
    reader, writer = mock_stream_factory(peercert=cert)

    async def _selective_open_connection(host: str, **_: object) -> tuple[AsyncMock, MagicMock]:
        if host == "10.0.1.99":
            raise TimeoutError()
        return reader, writer

    scheduler = ProbeScheduler(config=cfg, metrics=metrics)
    with patch("asyncio.open_connection", side_effect=_selective_open_connection):
        results = await scheduler.run_once()

    assert len(results) == 2

    healthy_up = isolated_registry.get_sample_value(
        "netdevops_probe_up",
        {"target": "healthy-edge", "check_type": "tls", "site": "dc-1", "role": "edge"},
    )
    dead_up = isolated_registry.get_sample_value(
        "netdevops_probe_up",
        {"target": "dead-edge", "check_type": "tls", "site": "dc-2", "role": "edge"},
    )
    dead_errors = isolated_registry.get_sample_value(
        "netdevops_probe_errors_total",
        {"target": "dead-edge", "check_type": "tls", "reason": "timeout"},
    )
    expiry_days = isolated_registry.get_sample_value(
        "netdevops_tls_cert_expiry_days",
        {"target": "healthy-edge", "site": "dc-1", "issuer": "DigiCert"},
    )

    assert healthy_up == 1.0
    assert dead_up == 0.0
    assert dead_errors == 1.0
    assert expiry_days is not None and 29.9 <= expiry_days <= 30.1