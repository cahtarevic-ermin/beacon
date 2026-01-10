"""Beacon API - Website Analysis Engine."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import health_router, scans_router
from config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Code before `yield` runs on startup.
    Code after `yield` runs on shutdown.
    """
    # Startup: You could initialize connections, warm caches, etc.
    print(f"Starting {settings.app_name}...")
    yield
    # Shutdown: Clean up resources
    print(f"Shutting down {settings.app_name}...")


app = FastAPI(
    title="Beacon API",
    description="Website analysis engine for performance, SEO, security, and asset auditing.",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure CORS (adjust origins for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to API docs."""
    return {
        "service": "Beacon API",
        "docs": "/docs",
        "health": "/api/v1/health",
    }
