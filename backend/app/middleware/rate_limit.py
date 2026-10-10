import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.security import decode_access_token


@dataclass(frozen=True)
class Rule:
    name: str
    method: str
    pattern: re.Pattern[str]
    limit: int
    window_seconds: int
    per_user: bool = False


RULES = (
    Rule("register", "POST", re.compile(r"^/api/auth/register$"), 5, 60),
    Rule("login", "POST", re.compile(r"^/api/auth/login$"), 10, 60),
    Rule("start_scan", "POST", re.compile(r"^/api/projects/[^/]+/scans$"), 20, 3600, per_user=True),
    Rule(
        "ai_analysis",
        "POST",
        re.compile(r"^/api/projects/[^/]+/scans/[^/]+/ai-analysis$"),
        6,
        3600,
        per_user=True,
    ),
)
GLOBAL_LIMIT = 600
GLOBAL_WINDOW_SECONDS = 60
PURGE_THRESHOLD = 10000


class SlidingWindowStore:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: int) -> int | None:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > PURGE_THRESHOLD:
                self._purge(now)
            hits = self._hits[key]
            while hits and now - hits[0] >= window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return max(1, int(window_seconds - (now - hits[0])) + 1)
            hits.append(now)
            return None

    def _purge(self, now: float) -> None:
        stale = [key for key, hits in self._hits.items() if not hits or now - hits[-1] >= 3600]
        for key in stale:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


store = SlidingWindowStore()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _identity(request: Request, per_user: bool) -> str:
    if per_user:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            user_id = decode_access_token(header[7:].strip())
            if user_id is not None:
                return f"user:{user_id}"
    return f"ip:{_client_ip(request)}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        retry_after = self._retry_after(request)
        if retry_after is not None:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    def _retry_after(self, request: Request) -> int | None:
        if request.method == "OPTIONS":
            return None
        retry = store.hit(f"global:{_client_ip(request)}", GLOBAL_LIMIT, GLOBAL_WINDOW_SECONDS)
        if retry is not None:
            return retry
        for rule in RULES:
            if rule.method == request.method and rule.pattern.match(request.url.path):
                key = f"{rule.name}:{_identity(request, rule.per_user)}"
                return store.hit(key, rule.limit, rule.window_seconds)
        return None