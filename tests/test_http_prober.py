from __future__ import annotations

import socket

import httpx
import respx

from app.config import TargetConfig
from app.probers.http import probe_http


@respx.mock
async def test_probe_http_200_ok() -> None:
    target = TargetConfig(name="auth-api", url="https://auth.internal.example.com/health", checks=["http"])
    respx.get("https://auth.internal.example.com/health").mock(
        return_value=httpx.Response(200, json={"status": "healthy"})
    )

    result = await probe_http(target, timeout=2.0)

    assert result.success is True
    assert result.error_reason is None
    assert result.details["status_code"] == 200


@respx.mock
async def test_probe_http_5xx_failure() -> None:
    target = TargetConfig(name="auth-api", url="https://auth.internal.example.com/health", checks=["http"])
    respx.get("https://auth.internal.example.com/health").mock(
        return_value=httpx.Response(503, text="Service Unavailable")
    )

    result = await probe_http(target, timeout=2.0)

    assert result.success is False
    assert result.error_reason == "http_5xx"
    assert result.details["status_code"] == 503


@respx.mock
async def test_probe_http_4xx_failure() -> None:
    target = TargetConfig(name="auth-api", url="https://auth.internal.example.com/health", checks=["http"])
    respx.get("https://auth.internal.example.com/health").mock(
        return_value=httpx.Response(404, text="Not Found")
    )

    result = await probe_http(target, timeout=2.0)

    assert result.success is False
    assert result.error_reason == "http_4xx"
    assert result.details["status_code"] == 404


@respx.mock
async def test_probe_http_timeout() -> None:
    target = TargetConfig(name="slow-api", url="https://slow.internal.example.com/health", checks=["http"])
    respx.get("https://slow.internal.example.com/health").mock(
        side_effect=httpx.ReadTimeout("timed out")
    )

    result = await probe_http(target, timeout=1.0)

    assert result.success is False
    assert result.error_reason == "timeout"


@respx.mock
async def test_probe_http_dns_error() -> None:
    target = TargetConfig(name="missing-dns", url="https://nxdomain.internal/health", checks=["http"])
    connect_exc = httpx.ConnectError("Name or service not known")
    connect_exc.__cause__ = socket.gaierror(-2, "Name or service not known")

    respx.get("https://nxdomain.internal/health").mock(side_effect=connect_exc)

    result = await probe_http(target, timeout=1.0)

    assert result.success is False
    assert result.error_reason == "dns_error"