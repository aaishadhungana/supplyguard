import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.insights import router as insights_router
from app.api.projects import router as projects_router
from app.api.scans import router as scans_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_logging import RequestLoggingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("supplyguard")

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware, production=settings.is_production)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Request-ID", "Retry-After"],
)


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    logger.error("unhandled_error request_id=%s path=%s", request_id, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
    )


app.include_router(health_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(projects_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(insights_router, prefix="/api")