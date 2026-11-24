from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config import CheckType


@dataclass(slots=True)
class ProbeResult:
    target: str
    check_type: CheckType
    success: bool
    duration_seconds: float
    error_reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)