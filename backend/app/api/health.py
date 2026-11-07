from fastapi import APIRouter, Depends, Response
from sqlalchemy.engine import Engine

from app.api.deps import get_engine_dep
from app.db import check_db
from app.schemas.health import ApiHealth, DatabaseHealth, HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut, responses={503: {"model": HealthOut}},
            summary="Is the API up and is PostgreSQL reachable?")
def health(response: Response, engine: Engine = Depends(get_engine_dep)):
    """Reports the API and the database separately, plus overall readiness.

    200 = ready. 503 = not ready (database unreachable). If this code runs, the API is up.
    The body never contains error text, host names or credentials; those go to the log.
    """
    database_up, latency_ms = check_db(engine)
    response.headers["Cache-Control"] = "no-store"
    if not database_up:
        response.status_code = 503
    return HealthOut(
        status="ready" if database_up else "not_ready",
        api=ApiHealth(),
        database=DatabaseHealth(status="up" if database_up else "down", latency_ms=latency_ms),
    )
