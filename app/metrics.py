from __future__ import annotations

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram


class MonitorMetrics:
    """Prometheus metric definitions and helper recorders for network/TLS probes."""

    LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self, registry: CollectorRegistry = REGISTRY) -> None:
        self.registry = registry

        self.probe_up = Gauge(
            name="netdevops_probe_up",
            documentation="Whether the last probe succeeded (1 = up, 0 = down).",
            labelnames=["target", "check_type", "site", "role"],
            registry=registry,
        )

        self.probe_duration_seconds = Histogram(
            name="netdevops_probe_duration_seconds",
            documentation="Probe execution duration in seconds.",
            labelnames=["target", "check_type", "site"],
            buckets=self.LATENCY_BUCKETS,
            registry=registry,
        )

        self.tls_cert_expiry_days = Gauge(
            name="netdevops_tls_cert_expiry_days",
            documentation="Remaining days until the peer TLS certificate expires.",
            labelnames=["target", "site", "issuer"],
            registry=registry,
        )

        self.probe_errors_total = Counter(
            name="netdevops_probe_errors_total",
            documentation="Total failed probes categorized by failure reason.",
            labelnames=["target", "check_type", "reason"],
            registry=registry,
        )

    def record_probe(
        self,
        *,
        target: str,
        check_type: str,
        site: str,
        role: str,
        success: bool,
        duration_seconds: float,
        error_reason: str | None = None,
    ) -> None:
        self.probe_up.labels(
            target=target,
            check_type=check_type,
            site=site,
            role=role,
        ).set(1.0 if success else 0.0)

        self.probe_duration_seconds.labels(
            target=target,
            check_type=check_type,
            site=site,
        ).observe(duration_seconds)

        if not success:
            self.probe_errors_total.labels(
                target=target,
                check_type=check_type,
                reason=error_reason or "unknown_error",
            ).inc()

    def record_tls_expiry(
        self,
        *,
        target: str,
        site: str,
        issuer: str,
        days_remaining: float,
    ) -> None:
        self.tls_cert_expiry_days.labels(
            target=target,
            site=site,
            issuer=issuer,
        ).set(days_remaining)