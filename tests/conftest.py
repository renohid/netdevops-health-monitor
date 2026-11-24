from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from prometheus_client import CollectorRegistry

from app.config import MonitorConfig, MonitorDefaults, TargetConfig, TargetTags
from app.metrics import MonitorMetrics


def format_cert_time(days_offset: float) -> str:
    """Format a UTC timestamp offset into OpenSSL's ASN.1 notAfter string format."""
    target_dt = datetime.now(UTC) + timedelta(days=days_offset)
    return target_dt.strftime("%b %d %H:%M:%S %Y GMT")


@pytest.fixture
def isolated_registry() -> CollectorRegistry:
    return CollectorRegistry()


@pytest.fixture
def metrics(isolated_registry: CollectorRegistry) -> MonitorMetrics:
    return MonitorMetrics(registry=isolated_registry)


@pytest.fixture
def sample_targets() -> list[TargetConfig]:
    return [
        TargetConfig(
            name="core-gateway-01",
            host="10.10.1.1",
            port=443,
            checks=["tcp", "tls"],
            tags=TargetTags(site="dc-east", role="edge"),
        ),
        TargetConfig(
            name="auth-api-prod",
            url="https://auth.internal.example.com/health",
            checks=["http", "tls"],
            tags=TargetTags(site="cloud", role="api"),
        ),
    ]


@pytest.fixture
def monitor_config(sample_targets: list[TargetConfig]) -> MonitorConfig:
    return MonitorConfig(
        defaults=MonitorDefaults(
            interval_seconds=15.0,
            timeout_seconds=2.0,
            max_concurrency=10,
        ),
        targets=sample_targets,
    )


@pytest.fixture
def mock_stream_factory() -> Callable[..., tuple[AsyncMock, MagicMock]]:
    """Build mock (StreamReader, StreamWriter) pairs with optional TLS cert metadata."""

    def _factory(
        *,
        peercert: dict[str, Any] | None = None,
        tls_version: str = "TLSv1.3",
    ) -> tuple[AsyncMock, MagicMock]:
        reader = AsyncMock()
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        ssl_obj = MagicMock()
        ssl_obj.version.return_value = tls_version

        def _get_extra_info(key: str, default: Any = None) -> Any:
            if key == "peercert":
                return peercert
            if key == "ssl_object":
                return ssl_obj
            return default

        writer.get_extra_info.side_effect = _get_extra_info
        return reader, writer

    return _factory