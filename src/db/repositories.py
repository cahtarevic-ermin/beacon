"""Repository pattern for database operations."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    AnalysisResult,
    AnalyzerType,
    Category,
    Recommendation,
    Scan,
    ScanStatus,
    Severity,
)


class ScanRepository:
    """Handles all Scan-related database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, url: str, metadata: dict | None = None) -> Scan:
        """Create a new scan record."""
        scan = Scan(
            url=url,
            status=ScanStatus.PENDING,
            metadata_=metadata,
        )
        self.session.add(scan)
        await self.session.flush()  # Assigns the ID without committing
        return scan

    async def get_by_id(self, scan_id: uuid.UUID) -> Scan | None:
        """Retrieve a scan by its ID."""
        result = await self.session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def update_status(
        self,
        scan_id: uuid.UUID,
        status: ScanStatus,
        error_message: str | None = None,
    ) -> None:
        """Update the status of a scan."""
        scan = await self.get_by_id(scan_id)
        if scan:
            scan.status = status
            if status == ScanStatus.RUNNING:
                scan.started_at = datetime.now(timezone.utc)
            elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                scan.completed_at = datetime.now(timezone.utc)
            if error_message:
                scan.error_message = error_message
            await self.session.flush()

    async def list_recent(self, limit: int = 20) -> list[Scan]:
        """Get the most recent scans."""
        result = await self.session.execute(
            select(Scan).order_by(Scan.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())


class AnalysisResultRepository:
    """Handles AnalysisResult database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        scan_id: uuid.UUID,
        analyzer_type: AnalyzerType,
        score: float | None = None,
        metrics: dict | None = None,
        raw_data: dict | None = None,
    ) -> AnalysisResult:
        """Store an analysis result."""
        result = AnalysisResult(
            scan_id=scan_id,
            analyzer_type=analyzer_type,
            score=score,
            metrics=metrics,
            raw_data=raw_data,
        )
        self.session.add(result)
        await self.session.flush()
        return result

    async def get_by_scan(self, scan_id: uuid.UUID) -> list[AnalysisResult]:
        """Get all analysis results for a scan."""
        result = await self.session.execute(
            select(AnalysisResult).where(AnalysisResult.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def get_by_scan_and_type(
        self,
        scan_id: uuid.UUID,
        analyzer_type: AnalyzerType,
    ) -> AnalysisResult | None:
        """Get a specific analyzer's result for a scan."""
        result = await self.session.execute(
            select(AnalysisResult).where(
                AnalysisResult.scan_id == scan_id,
                AnalysisResult.analyzer_type == analyzer_type,
            )
        )
        return result.scalar_one_or_none()


class RecommendationRepository:
    """Handles Recommendation database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        scan_id: uuid.UUID,
        category: Category,
        severity: Severity,
        source_analyzer: AnalyzerType,
        title: str,
        description: str,
        fix_suggestion: str,
        reference_url: str | None = None,
    ) -> Recommendation:
        """Create a recommendation."""
        recommendation = Recommendation(
            scan_id=scan_id,
            category=category,
            severity=severity,
            source_analyzer=source_analyzer,
            title=title,
            description=description,
            fix_suggestion=fix_suggestion,
            reference_url=reference_url,
        )
        self.session.add(recommendation)
        await self.session.flush()
        return recommendation

    async def create_many(
        self,
        recommendations: list[dict],
    ) -> list[Recommendation]:
        """Bulk create recommendations."""
        objects = [Recommendation(**rec) for rec in recommendations]
        self.session.add_all(objects)
        await self.session.flush()
        return objects

    async def get_by_scan(
        self,
        scan_id: uuid.UUID,
        severity: Severity | None = None,
    ) -> list[Recommendation]:
        """Get recommendations for a scan, optionally filtered by severity."""
        query = select(Recommendation).where(Recommendation.scan_id == scan_id)
        if severity:
            query = query.where(Recommendation.severity == severity)
        query = query.order_by(Recommendation.severity)  # High → Medium → Low
        result = await self.session.execute(query)
        return list(result.scalars().all())
