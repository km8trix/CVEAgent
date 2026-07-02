"""FastAPI application factory."""

from fastapi import FastAPI

from palisade.api.routes import health, scans


def create_app() -> FastAPI:
    app = FastAPI(title="Palisade", version="0.1.0")
    app.include_router(health.router)
    app.include_router(scans.router)
    return app


app = create_app()
