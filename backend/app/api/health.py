from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
def health(response: Response, db: Session = Depends(get_db)) -> dict[str, str]:
    settings = get_settings()
    try:
        db.execute(text("SELECT 1"))
        database = "up"
    except SQLAlchemyError:
        database = "down"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if database == "up" else "degraded",
        "database": database,
        "version": settings.app_version,
        "environment": settings.environment,
    }