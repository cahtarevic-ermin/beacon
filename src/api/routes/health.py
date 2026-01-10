"""Health check endpoint."""

from fastapi import APIRouter

from api.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check if the service is running and healthy.",
)
async def health_check() -> HealthResponse:
    """Return service health status."""
    return HealthResponse()
