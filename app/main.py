from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.core.config import settings
from app.core.logging import logger, setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """App lifespan event handler for startup and shutdown logging."""
    setup_logging()
    logger.info(
        "Starting %s in %s mode (debug=%s)",
        settings.APP_NAME,
        settings.ENVIRONMENT,
        settings.DEBUG,
    )
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    lifespan=lifespan,
)

app.include_router(health_router)


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    """Root endpoint welcoming users to the service."""
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "docs": "/docs",
    }
