from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.config import MonitorConfig, load_config
from app.metrics import MonitorMetrics
from app.scheduler import ProbeScheduler


def create_app(
    config: MonitorConfig | None = None,
    metrics: MonitorMetrics | None = None,
    start_scheduler: bool = True,
) -> FastAPI:
    """Application factory supporting isolated registries and configs for testing."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        resolved_config = config or load_config()
        resolved_metrics = metrics or MonitorMetrics()
        scheduler = ProbeScheduler(config=resolved_config, metrics=resolved_metrics)

        application.state.config = resolved_config
        application.state.metrics = resolved_metrics
        application.state.scheduler = scheduler

        if start_scheduler:
            await scheduler.start()

        try:
            yield
        finally:
            await scheduler.stop()

    application = FastAPI(
        title="NetDevOps Health Monitor",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.get("/healthz", tags=["system"])
    async def healthz(request: Request) -> dict[str, Any]:
        scheduler: ProbeScheduler = request.app.state.scheduler
        cfg: MonitorConfig = request.app.state.config
        return {
            "status": "ok",
            "targets_configured": len(cfg.targets),
            "last_cycle_at": (
                scheduler.last_cycle_at.isoformat() if scheduler.last_cycle_at else None
            ),
        }

    @application.get("/metrics", tags=["observability"])
    async def metrics_endpoint(request: Request) -> Response:
        monitor_metrics: MonitorMetrics = request.app.state.metrics
        payload = generate_latest(monitor_metrics.registry)
        return Response(content=payload, media_type=CONTENT_TYPE_LATEST)

    @application.get("/api/v1/targets", tags=["probes"])
    async def list_targets(request: Request) -> dict[str, Any]:
        scheduler: ProbeScheduler = request.app.state.scheduler
        return {
            "last_cycle_at": (
                scheduler.last_cycle_at.isoformat() if scheduler.last_cycle_at else None
            ),
            "targets": scheduler.get_target_snapshots(),
        }

    @application.post("/api/v1/probes/run", tags=["probes"])
    async def trigger_probe_cycle(request: Request) -> dict[str, Any]:
        scheduler: ProbeScheduler = request.app.state.scheduler
        results = await scheduler.run_once()
        return {
            "executed": len(results),
            "last_cycle_at": (
                scheduler.last_cycle_at.isoformat() if scheduler.last_cycle_at else None
            ),
            "targets": scheduler.get_target_snapshots(),
        }

    return application


app = create_app()