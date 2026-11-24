from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from app.config import MonitorConfig
from app.main import create_app
from app.metrics import MonitorMetrics
from tests.conftest import format_cert_time


@pytest.fixture
async def api_client(
    monitor_config: MonitorConfig,
    metrics: MonitorMetrics,
) -> AsyncIterator[httpx.AsyncClient]:
    """Spin up the FastAPI app with lifespan initialized and background loop disabled."""
    app = create_app(config=monitor_config, metrics=metrics, start_scheduler=False)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client


async def test_healthz_endpoint(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/healthz")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["targets_configured"] == 2
    assert payload["last_cycle_at"] is None


@respx.mock
async def test_trigger_probes_and_scrape_metrics(
    api_client: httpx.AsyncClient,
    mock_stream_factory: Callable[..., tuple[AsyncMock, MagicMock]],
) -> None:
    cert = {
        "issuer": ((("commonName", "R11"),),),
        "notAfter": format_cert_time(days_offset=60.0),
    }
    reader, writer = mock_stream_factory(peercert=cert)

    respx.get("https://auth.internal.example.com/health").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
        run_resp = await api_client.post("/api/v1/probes/run")

    assert run_resp.status_code == 200
    assert run_resp.json()["executed"] == 4  # core-gateway (tcp, tls) + auth-api (http, tls)

    # Verify JSON target snapshot endpoint
    targets_resp = await api_client.get("/api/v1/targets")
    assert targets_resp.status_code == 200
    targets_data = {item["name"]: item for item in targets_resp.json()["targets"]}
    assert targets_data["core-gateway-01"]["checks"]["tcp"]["status"] == "up"
    assert targets_data["core-gateway-01"]["checks"]["tls"]["status"] == "up"
    assert targets_data["auth-api-prod"]["checks"]["http"]["status"] == "up"

    # Verify Prometheus /metrics exposition format
    metrics_resp = await api_client.get("/metrics")
    assert metrics_resp.status_code == 200
    assert "text/plain" in metrics_resp.headers["content-type"]

    body = metrics_resp.text
    assert 'netdevops_probe_up{check_type="tcp",role="edge",site="dc-east",target="core-gateway-01"} 1.0' in body
    assert 'netdevops_probe_up{check_type="http",role="api",site="cloud",target="auth-api-prod"} 1.0' in body
    assert 'netdevops_tls_cert_expiry_days{issuer="R11",site="dc-east",target="core-gateway-01"}' in body