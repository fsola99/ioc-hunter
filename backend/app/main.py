from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .dependencies import SESSION_COOKIE
from .errors import ProviderError
from .ioc import UnrecognizedIoCError
from .routers import health, lookup

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

app = FastAPI(
    title="IoC Hunter",
    description=(
        "Threat intelligence lookups for file hashes, IP addresses, domains and URLs, "
        "normalised into one report shape and enriched with MITRE ATT&CK mitigations."
    ),
    version=health.VERSION,
)

settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "DELETE"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(lookup.router)


@app.middleware("http")
async def attach_session_cookie(request: Request, call_next):
    """Ensure every response carries the session cookie its history is keyed by."""
    response = await call_next(request)
    minted = getattr(request.state, "session_id", None)
    if minted and SESSION_COOKIE not in request.cookies:
        response.set_cookie(
            SESSION_COOKIE, minted, httponly=True, samesite="lax", max_age=60 * 60 * 24 * 7
        )
    return response


@app.exception_handler(UnrecognizedIoCError)
async def handle_unrecognized_ioc(_: Request, exc: UnrecognizedIoCError) -> JSONResponse:
    """Return 422 with the reason an input was not accepted as an indicator."""
    return JSONResponse(status_code=422, content={"detail": str(exc), "kind": "unrecognized"})


@app.exception_handler(ProviderError)
async def handle_provider_error(_: Request, exc: ProviderError) -> JSONResponse:
    """Return the status the failing provider maps to, with its message."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc), "provider": exc.provider, "kind": "provider"},
    )


if FRONTEND_DIST.is_dir():
    app.mount(
        "/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets"
    )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str) -> FileResponse:
        """Serve the built single-page frontend."""
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")

else:
    logger.info("No built frontend at %s; serving the API only.", FRONTEND_DIST)
