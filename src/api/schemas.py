"""Pydantic schemas for API request/response validation."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# =============================================================================
# Request Schemas (what clients send to us)
# =============================================================================


class ScanCreateRequest(BaseModel):
    """Request body for creating a new scan."""

    url: HttpUrl = Field(
        ...,
        description="The URL of the website to scan",
        examples=["https://example.com"],
    )
    metadata: dict | None = Field(
        default=None,
        description="Optional metadata to attach to the scan",
        examples=[{"user_agent": "mobile", "viewport": "1920x1080"}],
    )


# =============================================================================
# Response Schemas (what we send back to clients)
# =============================================================================


class AnalysisResultResponse(BaseModel):
    """Response schema for a single analysis result."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    analyzer_type: str
    score: float | None
    metrics: dict | None
    created_at: datetime


class RecommendationResponse(BaseModel):
    """Response schema for a single recommendation."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    category: str
    severity: str
    source_analyzer: str
    title: str
    description: str
    fix_suggestion: str
    reference_url: str | None


class ScanResponse(BaseModel):
    """Response schema for a scan (without nested results)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    status: str
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    metadata: dict | None = Field(alias="metadata_")


class ScanDetailResponse(ScanResponse):
    """Response schema for a scan with full details."""

    analysis_results: list[AnalysisResultResponse] = []
    recommendations: list[RecommendationResponse] = []


class ScanCreatedResponse(BaseModel):
    """Response when a scan is successfully queued."""

    id: uuid.UUID
    url: str
    status: str
    message: str = "Scan queued successfully"


# =============================================================================
# List Response Wrappers
# =============================================================================


class ScanListResponse(BaseModel):
    """Response for listing multiple scans."""

    scans: list[ScanResponse]
    count: int


class RecommendationListResponse(BaseModel):
    """Response for listing recommendations."""

    recommendations: list[RecommendationResponse]
    count: int


# =============================================================================
# Health Check
# =============================================================================


class HealthResponse(BaseModel):
    """Response for health check endpoint."""

    status: str = "healthy"
    service: str = "beacon"
    version: str = "0.1.0"
