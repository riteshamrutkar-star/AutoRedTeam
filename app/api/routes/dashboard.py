from pathlib import Path
from fastapi import APIRouter, status
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["Research Dashboard Interface"])

TEMPLATE_PATH = Path(__file__).parent.parent.parent / "templates" / "dashboard.html"


@router.get(
    "/dashboard",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    summary="Security Research Dashboard HTML Interface",
    description="Loads the single-page HTML research visualization dashboard.",
)
def get_dashboard_ui() -> HTMLResponse:
    """Returns the main dashboard HTML interface."""
    if TEMPLATE_PATH.exists():
        html_content = TEMPLATE_PATH.read_text(encoding="utf-8")
        return HTMLResponse(content=html_content)
    return HTMLResponse(content="<h1>Dashboard Template Not Found</h1>", status_code=500)
