import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Match

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.core.config import get_settings
from app.core.security import AuthError, verify_access_token
from app.core.tenant import TenantContext
from app.db.session import close_db

settings = get_settings()

PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/v1/health",
        "/v1/auth/token",
    }
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup actions (e.g., connection pools) can be initialized here
    yield
    # Shutdown actions clean up here
    await close_db()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Multi-tenant Enterprise RAG platform for MedInsure Labs",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def tenant_auth_middleware(request: Request, call_next):
    """Authenticate protected routes using Bearer JWT and attach TenantContext.

    Public routes (/health, /v1/health, /v1/auth/token) bypass authentication.
    Non-existent routes pass through to router for standard 404 handling.
    All other application routes strictly enforce a valid Bearer JWT.
    """
    path = request.url.path.rstrip("/") or "/"
    if path in PUBLIC_PATHS:
        return await call_next(request)

    # Check if the requested route exists in application routing
    has_match = False
    for route in request.app.routes:
        match, _ = route.matches(request.scope)
        if match == Match.FULL:
            has_match = True
            break

    # If the route does not exist at all, let router handle standard 404
    if not has_match:
        return await call_next(request)

    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"X-Request-ID": request_id},
            content={
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Missing or invalid bearer token.",
                    "request_id": request_id,
                }
            },
        )

    token = auth_header[7:].strip()
    try:
        claims = verify_access_token(token)
    except AuthError as err:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"X-Request-ID": request_id},
            content={
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": str(err),
                    "request_id": request_id,
                }
            },
        )

    # Attach verified TenantContext to request.state
    request.state.tenant_context = TenantContext(
        tenant_id=uuid.UUID(claims["tenant_id"]),
        user_id=uuid.UUID(claims["user_id"]),
        role=claims["role"],
        groups=claims["groups"],
    )

    return await call_next(request)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=exc.status_code,
        headers={"X-Request-ID": request_id},
        content={
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": exc.detail,
                "request_id": request_id,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        headers={"X-Request-ID": request_id},
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": str(exc.errors()),
                "request_id": request_id,
            }
        },
    )


# Mount health check endpoints at both /health and /v1/health
app.include_router(health_router, prefix="")
app.include_router(health_router, prefix="/v1")

# Mount auth endpoints at /v1/auth
app.include_router(auth_router, prefix="/v1/auth")


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/v1/me", tags=["Authentication"])
async def get_current_user_context(request: Request):
    """Return the verified TenantContext for the authenticated request."""
    ctx: TenantContext = request.state.tenant_context
    return {
        "tenant_id": str(ctx.tenant_id),
        "user_id": str(ctx.user_id),
        "role": ctx.role,
        "groups": ctx.groups,
    }
