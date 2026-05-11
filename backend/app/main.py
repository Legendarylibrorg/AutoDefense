from __future__ import annotations

import base64
import ipaddress
import hmac
import logging
import os
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.core.logging import configure_logging
from app.core.redis_client import close_pool, get_redis
from app.settings import settings

PUBLIC_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

_PRODUCTION_LIKE_ENVS = frozenset({"production", "staging", "prod"})


def _client_host_for_rate_limit(request: Request) -> str:
    """Client IP for rate limiting. Use X-Forwarded-For only when trusted_proxy_hops > 0."""
    direct = request.client.host if request.client else "unknown"
    if settings.trusted_proxy_hops <= 0:
        return direct
    xff = request.headers.get("x-forwarded-for")
    if not xff or not xff.strip():
        return direct
    first = xff.split(",")[0].strip()
    if not first:
        return direct
    host = first.split("%", 1)[0].strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return direct
    return host


# In-process fixed-window fallback when Redis is unavailable (stricter cap than Redis path).
_mem_lock = threading.Lock()
_mem_counts: dict[tuple[str, int], int] = {}


def _memory_rate_limit_allow(client: str, bucket: int, limit: int) -> bool:
    key = (client, bucket)
    with _mem_lock:
        n = _mem_counts.get(key, 0) + 1
        _mem_counts[key] = n
        if len(_mem_counts) > 50_000:
            cut = bucket - 2
            for k in list(_mem_counts.keys()):
                if k[1] < cut:
                    del _mem_counts[k]
                if len(_mem_counts) <= 40_000:
                    break
        return n <= limit


def _enforce_runtime_secrets() -> None:
    """Fail closed outside local: require API key; production-like envs need scanner HMAC."""
    env = settings.environment.strip().lower()

    if not settings.is_local and not settings.api_key:
        raise RuntimeError(
            "AUTODEFENSE_API_KEY is required unless AUTODEFENSE_ENVIRONMENT is local."
        )

    if env in _PRODUCTION_LIKE_ENVS:
        if not settings.scanner_hmac_key:
            raise RuntimeError(
                "AUTODEFENSE_SCANNER_HMAC_KEY is required when AUTODEFENSE_ENVIRONMENT is "
                "production, staging, or prod."
            )

    if not settings.is_local and settings.data_encryption_enabled and not settings.data_key_b64:
        raise RuntimeError(
            "AUTODEFENSE_DATA_KEY_B64 is required when AUTODEFENSE_DATA_ENCRYPTION_ENABLED is true "
            "and AUTODEFENSE_ENVIRONMENT is not local."
        )


# ---------------------------------------------------------------------------
# Request body size limit
# ---------------------------------------------------------------------------

MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413, content={"detail": "Request body too large"}
                    )
            except (ValueError, OverflowError):
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        elif request.method in ("POST", "PUT", "PATCH"):
            # Stream with a hard cap so chunked / unknown-length bodies cannot buffer past MAX.
            total = 0
            chunks: list[bytes] = []
            async for chunk in request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413, content={"detail": "Request body too large"}
                    )
                chunks.append(chunk)
            request._body = b"".join(chunks)
        return await call_next(request)


# ---------------------------------------------------------------------------
# API-key authentication (C1 fix)
# ---------------------------------------------------------------------------


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Bearer-token authentication for all non-public HTTP routes when an API key is set.
    `/health`, `/docs`, `/openapi.json`, and `/redoc` are exempt. When no API key is
    configured (e.g. local dev), auth is disabled with a startup warning.
    """

    def __init__(self, app, *, api_key: str | None):
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next):
        if not self.api_key:
            return await call_next(request)

        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        if request.scope.get("type") == "websocket":
            token = ""
            protocols = request.headers.get("sec-websocket-protocol", "")
            for proto in protocols.split(","):
                p = proto.strip()
                if p.startswith("auth."):
                    token = p.removeprefix("auth.")
                    break
        else:
            auth = request.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()

        if not token or not hmac.compare_digest(token, self.api_key):
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)


# ---------------------------------------------------------------------------
# Rate limiter — Redis fixed-window (shared across workers / replicas)
# ---------------------------------------------------------------------------


class RedisRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP fixed-window counter in Redis so multiple uvicorn workers or replicas
    share one limit. If Redis errors, fall back to an in-process counter with a
    lower limit so abuse cannot bypass throttling entirely.
    """

    def __init__(self, app, *, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._fallback_limit = max(1, max_requests // 2)

    async def dispatch(self, request: Request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        client = _client_host_for_rate_limit(request)
        bucket = int(time.time()) // self.window_seconds
        key = f"autodefense:ratelimit:v1:{client}:{bucket}"

        try:
            redis = get_redis()
            current = await redis.incr(key)
            if current == 1:
                await redis.expire(key, self.window_seconds + 5)
            if current > self.max_requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again later."},
                    headers={"Retry-After": str(self.window_seconds)},
                )
        except Exception as exc:
            logging.getLogger("autodefense").warning(
                "Rate limit Redis check failed; using in-memory fallback (%s)",
                type(exc).__name__,
                extra={"event_type": "ratelimit", "action": "memory_fallback"},
            )
            if not _memory_rate_limit_allow(client, bucket, self._fallback_limit):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again later."},
                    headers={"Retry-After": str(self.window_seconds)},
                )

        return await call_next(request)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    configure_logging(settings.log_level)
    _enforce_runtime_secrets()
    logger = logging.getLogger("autodefense")

    if settings.data_encryption_enabled and not settings.data_key_b64:
        if settings.is_local:
            settings.data_key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
            logger.warning(
                "AUTODEFENSE_DATA_KEY_B64 not set; generated ephemeral at-rest key "
                "(data won't survive restarts)",
                extra={"event_type": "crypto", "action": "ephemeral_key_generated"},
            )

    if settings.transport_seal_enabled and not settings.transport_key_b64:
        logger.warning(
            "AUTODEFENSE_TRANSPORT_KEY_B64 not set; sealed endpoints will reject requests "
            "until a shared key is configured (run scripts/start.sh to auto-generate)",
            extra={"event_type": "crypto", "action": "transport_key_missing"},
        )

    if not settings.api_key:
        logger.warning(
            "AUTODEFENSE_API_KEY not set; all endpoints are UNAUTHENTICATED. "
            "Run scripts/start.sh to auto-generate or set AUTODEFENSE_API_KEY.",
            extra={"event_type": "security", "action": "auth_disabled"},
        )

    if not settings.scanner_hmac_key:
        logger.warning(
            "AUTODEFENSE_SCANNER_HMAC_KEY not set; scanner payloads will not be verified. "
            "Run scripts/start.sh to auto-generate.",
            extra={"event_type": "security", "action": "hmac_disabled"},
        )

    logger.info(
        "Starting backend (encryption=%s, sealed_transport=%s, auth=%s, scanner_hmac=%s)",
        "on" if settings.data_encryption_enabled else "off",
        "on" if settings.transport_seal_enabled and settings.transport_key_b64 else "off",
        "on" if settings.api_key else "OFF",
        "on" if settings.scanner_hmac_key else "OFF",
        extra={"event_type": "startup", "action": "boot"},
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await close_pool()

    app = FastAPI(
        title="Autonomous AI Defense System",
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.is_local else None,
        redoc_url="/redoc" if settings.is_local else None,
    )

    # Middleware order: outermost first → innermost last.
    # Starlette applies them bottom-up, so we add in reverse.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(RedisRateLimitMiddleware, max_requests=120, window_seconds=60)
    app.add_middleware(AuthMiddleware, api_key=settings.api_key)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],
    )

    # Sanitise validation errors — hide field internals outside local
    @app.exception_handler(RequestValidationError)
    async def _validation_error(_req: Request, exc: RequestValidationError):
        if settings.is_local:
            safe_errors = []
            for err in exc.errors():
                safe_errors.append(
                    {
                        "field": " → ".join(str(part) for part in err.get("loc", [])),
                        "message": err.get("msg", "validation error"),
                    }
                )
            return JSONResponse(status_code=422, content={"detail": safe_errors})
        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid request body"},
        )

    app.include_router(api_router)
    return app


app = create_app()
