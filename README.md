# NetDevOps Health Monitor

An asynchronous network, HTTP, and TLS certificate health monitor built with **FastAPI**, **Prometheus**, and **Grafana**.

Probes run on a decoupled `asyncio` background scheduler bounded by a concurrency semaphore, keeping `/metrics` scrapes fast and deterministic regardless of upstream network timeouts.

## Features

- **Multi-Protocol Async Probing:** Concurrent TCP socket reachability (`asyncio.open_connection`), TLS handshake and X.509 certificate expiry tracking (`ssl` / `notAfter`), and HTTP status/latency checks (`httpx.AsyncClient`).
- **Structured Failure Classification:** Categorizes faults into actionable Prometheus labels (`timeout`, `dns_error`, `refused`, `connect_error`, `tls_error`, `http_4xx`, `http_5xx`).
- **Typed YAML Configuration:** Targets, timeouts, concurrency limits, and metadata tags (`site`, `role`) validated at startup via Pydantic v2 (`targets.yaml`).
- **Turnkey Observability Stack:** Pre-configured Prometheus scrape jobs, 5 alerting rules (`deploy/prometheus/alerts.yml`), and an auto-provisioned Grafana dashboard (`deploy/grafana/`).
- **Mocked Async Test Suite:** 16 unit and API tests using `pytest-asyncio`, `respx`, and `unittest.mock` with isolated Prometheus registries.

## Repository Structure

```text
netdevops-health-monitor/
├── app/
│   ├── probers/
│   │   ├── __init__.py      # ProbeResult dataclass
│   │   ├── tcp.py           # Async TCP socket prober
│   │   ├── tls.py           # TLS handshake & certificate expiry parser
│   │   └── http.py          # Async HTTP prober with exception-chain inspection
│   ├── config.py            # Pydantic models & targets.yaml loader
│   ├── metrics.py           # Prometheus gauges, histograms, and counters
│   ├── scheduler.py         # Bounded asyncio background probe loop
│   └── main.py              # FastAPI application & lifespan hooks
├── deploy/
│   ├── prometheus/
│   │   ├── prometheus.yml   # Scrape configuration
│   │   └── alerts.yml       # Availability, TLS expiry, and P95 latency alerts
│   └── grafana/
│       ├── dashboards/      # Auto-provisioned NetDevOps dashboard JSON
│       └── provisioning/    # Datasource & dashboard provider configs
├── tests/                   # Mocked async tests (pytest)
├── targets.yaml             # Target definitions & probe settings
├── Dockerfile               # Non-root Python 3.12 container build
├── docker-compose.yml       # Full stack orchestration
└── pyproject.toml           # Dependencies & pytest settings