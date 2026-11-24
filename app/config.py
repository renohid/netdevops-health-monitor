from __future__ import annotations

import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, model_validator

CheckType = Literal["tcp", "tls", "http"]


class TargetTags(BaseModel):
    site: str = "default"
    role: str = "service"


class TargetConfig(BaseModel):
    name: str = Field(..., min_length=1)
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    url: str | None = None
    checks: list[CheckType] = Field(..., min_length=1)
    timeout_seconds: float | None = Field(default=None, gt=0)
    tags: TargetTags = Field(default_factory=TargetTags)

    @model_validator(mode="after")
    def validate_target_endpoints(self) -> TargetConfig:
        if "http" in self.checks and not self.url:
            raise ValueError(f"Target '{self.name}' requires 'url' when 'http' check is enabled.")

        if self.url:
            parsed = urlparse(self.url)
            if not parsed.scheme or not parsed.hostname:
                raise ValueError(f"Target '{self.name}' has an invalid URL: '{self.url}'.")
            if self.host is None:
                self.host = parsed.hostname
            if self.port is None:
                self.port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if any(check in self.checks for check in ("tcp", "tls")):
            if not self.host:
                raise ValueError(
                    f"Target '{self.name}' requires 'host' (or a valid 'url') for tcp/tls checks."
                )
            if self.port is None:
                self.port = 443

        return self


class MonitorDefaults(BaseModel):
    interval_seconds: float = Field(default=15.0, gt=0)
    timeout_seconds: float = Field(default=5.0, gt=0)
    max_concurrency: int = Field(default=20, ge=1)


class MonitorConfig(BaseModel):
    defaults: MonitorDefaults = Field(default_factory=MonitorDefaults)
    targets: list[TargetConfig] = Field(default_factory=list)

    def effective_timeout(self, target: TargetConfig) -> float:
        return target.timeout_seconds or self.defaults.timeout_seconds


def load_config(path: str | Path | None = None) -> MonitorConfig:
    config_path = Path(path or os.getenv("TARGETS_CONFIG_PATH", "targets.yaml"))
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    raw_data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    return MonitorConfig.model_validate(raw_data)