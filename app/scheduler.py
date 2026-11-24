from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from app.config import CheckType, MonitorConfig, TargetConfig
from app.metrics import MonitorMetrics
from app.probers import ProbeResult
from app.probers.http import probe_http
from app.probers.tcp import probe_tcp
from app.probers.tls import probe_tls

logger = logging.getLogger(__name__)


class ProbeScheduler:
    """Background async scheduler that executes probes and updates Prometheus metrics."""

    def __init__(
        self,
        config: MonitorConfig,
        metrics: MonitorMetrics,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self.metrics = metrics
        self._semaphore = asyncio.Semaphore(config.defaults.max_concurrency)
        self._external_http_client = http_client
        self._http_client: httpx.AsyncClient | None = http_client
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._latest_results: dict[tuple[str, CheckType], ProbeResult] = {}
        self.last_cycle_at: datetime | None = None

    async def _ensure_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(follow_redirects=True)
        return self._http_client

    async def run_single_probe(
        self,
        target: TargetConfig,
        check_type: CheckType,
    ) -> ProbeResult:
        """Execute one bounded probe, update metrics, and cache the latest result."""
        timeout = self.config.effective_timeout(target)

        async with self._semaphore:
            try:
                if check_type == "tcp":
                    result = await probe_tcp(target, timeout=timeout)
                elif check_type == "tls":
                    result = await probe_tls(target, timeout=timeout)
                elif check_type == "http":
                    client = await self._ensure_http_client()
                    result = await probe_http(target, timeout=timeout, client=client)
                else:
                    result = ProbeResult(
                        target=target.name,
                        check_type=check_type,
                        success=False,
                        duration_seconds=0.0,
                        error_reason="unsupported_check",
                    )
            except Exception as exc:
                logger.exception("Unexpected error probing %s [%s]: %s", target.name, check_type, exc)
                result = ProbeResult(
                    target=target.name,
                    check_type=check_type,
                    success=False,
                    duration_seconds=0.0,
                    error_reason="internal_error",
                )

        self.metrics.record_probe(
            target=target.name,
            check_type=check_type,
            site=target.tags.site,
            role=target.tags.role,
            success=result.success,
            duration_seconds=result.duration_seconds,
            error_reason=result.error_reason,
        )

        if check_type == "tls" and "tls_days_remaining" in result.details:
            self.metrics.record_tls_expiry(
                target=target.name,
                site=target.tags.site,
                issuer=str(result.details.get("tls_issuer", "unknown")),
                days_remaining=float(result.details["tls_days_remaining"]),
            )

        self._latest_results[(target.name, check_type)] = result
        return result

    async def run_once(self) -> list[ProbeResult]:
        """Run one full probe cycle across all configured targets concurrently."""
        tasks = [
            self.run_single_probe(target, check_type)
            for target in self.config.targets
            for check_type in target.checks
        ]
        if not tasks:
            self.last_cycle_at = datetime.now(UTC)
            return []

        results = await asyncio.gather(*tasks)
        self.last_cycle_at = datetime.now(UTC)
        return list(results)

    async def _loop(self) -> None:
        interval = self.config.defaults.interval_seconds
        while not self._stop_event.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def start(self) -> None:
        """Start the background probe loop."""
        if self._task is not None and not self._task.done():
            return
        self._stop_event.clear()
        await self._ensure_http_client()
        self._task = asyncio.create_task(self._loop(), name="netdevops-probe-scheduler")

    async def stop(self) -> None:
        """Signal the background loop to stop and clean up owned HTTP connections."""
        self._stop_event.set()
        if self._task is not None:
            await self._task
            self._task = None

        if self._http_client is not None and self._external_http_client is None:
            await self._http_client.aclose()
            self._http_client = None

    def get_target_snapshots(self) -> list[dict[str, Any]]:
        """Return the latest cached probe status for every configured target."""
        snapshots: list[dict[str, Any]] = []
        for target in self.config.targets:
            checks_status: dict[str, Any] = {}
            for check_type in target.checks:
                result = self._latest_results.get((target.name, check_type))
                if result is None:
                    checks_status[check_type] = {"status": "pending"}
                else:
                    checks_status[check_type] = {
                        "status": "up" if result.success else "down",
                        "duration_ms": round(result.duration_seconds * 1000, 2),
                        "error_reason": result.error_reason,
                        "details": result.details,
                    }

            snapshots.append(
                {
                    "name": target.name,
                    "host": target.host,
                    "port": target.port,
                    "url": target.url,
                    "tags": target.tags.model_dump(),
                    "checks": checks_status,
                }
            )
        return snapshots