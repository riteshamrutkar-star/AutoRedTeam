from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()


class HealthResponse(BaseModel):
    service_name: str
    status: str
    version: str
    environment: str


@router.get("/health", response_model=HealthResponse, tags=["System"])
def get_health() -> HealthResponse:
    """Check application status and metadata."""
    return HealthResponse(
        service_name=settings.APP_NAME,
        status="ok",
        version=settings.AUTOREDTEAM_VERSION,
        environment=settings.ENVIRONMENT,
    )
