"""Shape of GET /health: API and database are reported separately, plus overall readiness."""
from typing import Literal

from pydantic import BaseModel


class ApiHealth(BaseModel):
    status: Literal["up"] = "up"  # if this code runs at all, the API process is up


class DatabaseHealth(BaseModel):
    status: Literal["up", "down"]
    latency_ms: float | None = None


class HealthOut(BaseModel):
    status: Literal["ready", "not_ready"]
    api: ApiHealth
    database: DatabaseHealth
