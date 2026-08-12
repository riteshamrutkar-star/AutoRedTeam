from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from app.schemas.spec import NormalizedApiSpec
from app.services.openapi.loader import load_spec_from_bytes
from app.services.openapi.normalizer import process_spec_bytes
from app.services.openapi.validator import validate_openapi_spec

router = APIRouter(prefix="/api/v1/specifications", tags=["Specifications"])


class ValidationResponse(BaseModel):
    valid: bool
    title: str
    version: str
    endpoint_count: int


@router.post(
    "/parse",
    response_model=NormalizedApiSpec,
    summary="Parse and normalize an OpenAPI specification file",
    description="Upload an OpenAPI 3.x specification file (.json, .yaml, or .yml) to validate, dereference, and convert into AutoRedTeam's normalized representation.",
)
async def parse_specification(file: UploadFile = File(...)) -> NormalizedApiSpec:
    """Ingest and normalize an uploaded OpenAPI specification file."""
    content = await file.read()
    return process_spec_bytes(content, filename=file.filename)


@router.post(
    "/validate",
    response_model=ValidationResponse,
    summary="Validate an OpenAPI specification file",
    description="Upload an OpenAPI specification file to check structural compliance without full endpoint normalization.",
)
async def validate_specification(file: UploadFile = File(...)) -> ValidationResponse:
    """Validate an uploaded OpenAPI specification file."""
    content = await file.read()
    doc = load_spec_from_bytes(content, filename=file.filename)
    validate_openapi_spec(doc)
    
    paths_count = len(doc.get("paths", {})) if isinstance(doc.get("paths"), dict) else 0
    info_dict = doc.get("info", {})
    title = info_dict.get("title", "Untitled API") if isinstance(info_dict, dict) else "Untitled API"
    version = str(info_dict.get("version", "1.0.0")) if isinstance(info_dict, dict) else "1.0.0"

    return ValidationResponse(
        valid=True,
        title=title,
        version=version,
        endpoint_count=paths_count,
    )
