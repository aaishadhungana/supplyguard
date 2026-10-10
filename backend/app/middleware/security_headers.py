from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

MAX_BODY_BYTES = 6 * 1024 * 1024


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, production: bool) -> None:
        super().__init__(app)
        self.production = production

    async def dispatch(self, request: Request, call_next):
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            response = JSONResponse(status_code=413, content={"detail": "Request body too large"})
        else:
            response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        if self.production:
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response