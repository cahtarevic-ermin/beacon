"""Scan API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.schemas import (
    RecommendationListResponse,
    ScanCreatedResponse,
    ScanCreateRequest,
    ScanDetailResponse,
    ScanListResponse,
)
from db.models import Severity
from db.repositories import RecommendationRepository, ScanRepository
from db.session import get_db_session

from worker.tasks import run_full_scan

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "",
    response_model=ScanCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create a new scan",
    description="Queue a new website scan. Returns immediately with scan ID.",
)
async def create_scan(
    request: ScanCreateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> ScanCreatedResponse:
    """
    Create a new scan job.

    The scan is queued for async processing and this endpoint returns
    immediately with the scan ID. Poll GET /scans/{id} for status.
    """
    repo = ScanRepository(db)
    scan = await repo.create(
        url=str(request.url),
        metadata=request.metadata,
    )
    await db.commit()

    # Queue the scan task
    run_full_scan.delay(str(scan.id))

    return ScanCreatedResponse(
        id=scan.id,
        url=scan.url,
        status=scan.status.value,
    )


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List recent scans",
    description="Get a list of recent scans, newest first.",
)
async def list_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db_session),
) -> ScanListResponse:
    """List recent scans."""
    repo = ScanRepository(db)
    scans = await repo.list_recent(limit=limit)
    return ScanListResponse(
        scans=scans,
        count=len(scans),
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan details",
    description="Get full details of a scan including analysis results and recommendations.",
)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ScanDetailResponse:
    """Get a scan by ID with all its results."""
    repo = ScanRepository(db)
    scan = await repo.get_by_id(scan_id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    return ScanDetailResponse.model_validate(scan)


@router.get(
    "/{scan_id}/recommendations",
    response_model=RecommendationListResponse,
    summary="Get scan recommendations",
    description="Get recommendations for a specific scan, optionally filtered by severity.",
)
async def get_scan_recommendations(
    scan_id: uuid.UUID,
    severity: str | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> RecommendationListResponse:
    """Get recommendations for a scan."""
    # Verify scan exists
    scan_repo = ScanRepository(db)
    scan = await scan_repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    # Parse severity filter if provided
    severity_enum = None
    if severity:
        try:
            severity_enum = Severity(severity.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}. Must be one of: high, medium, low, info",
            )

    rec_repo = RecommendationRepository(db)
    recommendations = await rec_repo.get_by_scan(scan_id, severity=severity_enum)

    return RecommendationListResponse(
        recommendations=recommendations,
        count=len(recommendations),
    )
