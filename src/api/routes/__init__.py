"""API route exports."""

from api.routes.health import router as health_router
from api.routes.scans import router as scans_router

__all__ = ["health_router", "scans_router"]
