from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.api.routes.health import router as health_router
from app.api.routes.specifications import router as specs_router
from app.core.config import settings
from app.core.exceptions import OpenAPIException
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

# Exception handlers for OpenAPI ingestion domain errors
@app.exception_handler(OpenAPIException)
async def openapi_exception_handler(request: Request, exc: OpenAPIException) -> JSONResponse:
    logger.warning("OpenAPI ingestion error on %s: %s", request.url.path, exc.message)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": exc.__class__.__name__,
            "message": exc.message,
            "details": exc.details,
        },
    )


# Include routers
app.include_router(health_router)
app.include_router(specs_router)


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    """Root endpoint welcoming users to the service."""
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "docs": "/docs",
    }
