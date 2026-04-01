from __future__ import annotations

import base64
import hmac
import logging
import os
import time
from collections import OrderedDict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.core.logging import configure_logging
from app.core.redis_client import close_pool
from app.settings import settings

PUBLIC_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})


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
                    return JSONResponse(status_code=413, content={"detail": "Request body too large"})
            except (ValueError, OverflowError):
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        elif request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > MAX_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        return await call_next(request)


# ---------------------------------------------------------------------------
# API-key authentication (C1 fix)
# ---------------------------------------------------------------------------

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Bearer-token authentication for all mutating / sensitive endpoints.
    Read-only /health and docs are exempt.  When no API key is configured
    (e.g. local dev), auth is disabled with a startup warning.
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
            # Accept query param OR Sec-WebSocket-Protocol header for auth
            token = request.query_params.get("token", "")
            if not token:
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
# Rate limiter with bounded LRU eviction (C3 fix)
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory sliding-window rate limiter per client IP.
    Uses an LRU OrderedDict capped at max_clients to prevent memory exhaustion.
    """

    def __init__(
        self, app, *, max_requests: int = 120, window_seconds: int = 60, max_clients: int = 10_000
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.max_clients = max_clients
        self._hits: OrderedDict[str, list[float]] = OrderedDict()

    async def dispatch(self, request: Request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        cutoff = now - self.window

        if client in self._hits:
            self._hits.move_to_end(client)
        else:
            if len(self._hits) >= self.max_clients:
                self._hits.popitem(last=False)

        window = self._hits.setdefault(client, [])
        window[:] = [t for t in window if t > cutoff]

        if len(window) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(self.window)},
            )

        window.append(now)
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
    logger = logging.getLogger("autodefense")

    if settings.data_encryption_enabled and not settings.data_key_b64:
        settings.data_key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        logger.warning(
            "AUTODEFENSE_DATA_KEY_B64 not set; generated ephemeral at-rest key (data won't survive restarts)",
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
        docs_url="/docs" if settings.environment == "local" else None,
        redoc_url="/redoc" if settings.environment == "local" else None,
    )

    # Middleware order: outermost first → innermost last.
    # Starlette applies them bottom-up, so we add in reverse.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(RateLimitMiddleware, max_requests=120, window_seconds=60, max_clients=10_000)
    app.add_middleware(AuthMiddleware, api_key=settings.api_key)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],
    )

    # Sanitise validation errors — hide field internals (M fix)
    @app.exception_handler(RequestValidationError)
    async def _validation_error(_req: Request, exc: RequestValidationError):
        safe_errors = []
        for err in exc.errors():
            safe_errors.append({
                "field": " → ".join(str(l) for l in err.get("loc", [])),
                "message": err.get("msg", "validation error"),
            })
        return JSONResponse(status_code=422, content={"detail": safe_errors})

    app.include_router(api_router)
    return app


app = create_app()
