"""Celery tasks for running website scans."""

import uuid
from datetime import datetime, timezone

from celery import chain, group
from celery.utils.log import get_task_logger
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from config import settings
from db.models import AnalyzerType, Scan, ScanStatus
from db.repositories import AnalysisResultRepository, ScanRepository
from worker.celery_app import celery_app

# Logger for tasks
logger = get_task_logger(__name__)

# Synchronous database engine for Celery tasks
# (Celery doesn't play well with async, so we use sync SQLAlchemy here)
sync_database_url = settings.database_url.replace("+asyncpg", "+psycopg2")
sync_engine = create_engine(sync_database_url)
SyncSessionLocal = sessionmaker(bind=sync_engine)


def get_sync_session() -> Session:
    """Get a synchronous database session for Celery tasks."""
    return SyncSessionLocal()


@celery_app.task(bind=True, name="worker.tasks.run_full_scan")
def run_full_scan(self, scan_id: str) -> dict:
    """
    Main task that orchestrates a complete website scan.

    Uses Celery chord: run analyzers in parallel, then finalize.
    """
    scan_uuid = uuid.UUID(scan_id)
    logger.info(f"Starting full scan for {scan_id}")

    with get_sync_session() as session:
        # Get the scan record
        scan = session.get(Scan, scan_uuid)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return {"error": f"Scan {scan_id} not found"}

        url = scan.url

        # Update status to RUNNING
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        session.commit()

    # Use chord: run all analyzers in parallel, then call finalize_scan
    from celery import chord

    workflow = chord(
        [
            run_lighthouse_audit.s(scan_id, url),
            run_seo_analysis.s(scan_id, url),
            run_security_audit.s(scan_id, url),
            run_asset_analysis.s(scan_id, url),
        ],
        finalize_scan.s(scan_id),  # Called after all complete
    )

    workflow.apply_async()

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": "Analyzers dispatched",
    }


@celery_app.task(bind=True, name="worker.tasks.finalize_scan")
def finalize_scan(self, analyzer_results: list, scan_id: str) -> dict:
    """
    Called after all analyzers complete.

    Generates recommendations and marks scan as complete.

    Args:
        analyzer_results: List of results from each analyzer (passed by chord)
        scan_id: UUID of the scan
    """
    scan_uuid = uuid.UUID(scan_id)
    logger.info(f"Finalizing scan {scan_id}")

    try:
        # Generate recommendations
        generate_recommendations(scan_id)

        # Mark scan as completed
        with get_sync_session() as session:
            scan = session.get(Scan, scan_uuid)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            session.commit()

        logger.info(f"Scan {scan_id} completed successfully")

        return {
            "scan_id": scan_id,
            "status": "completed",
            "analyzer_results": analyzer_results,
        }

    except Exception as e:
        logger.exception(f"Scan {scan_id} finalization failed: {e}")

        with get_sync_session() as session:
            scan = session.get(Scan, scan_uuid)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            session.commit()

        return {
            "scan_id": scan_id,
            "status": "failed",
            "error": str(e),
        }


@celery_app.task(bind=True, name="worker.tasks.run_lighthouse_audit")
def run_lighthouse_audit(self, scan_id: str, url: str) -> dict:
    """
    Run Lighthouse performance audit.
    """
    logger.info(f"Running Lighthouse audit for {url}")

    from analyzers.lighthouse import LighthouseAnalyzer

    analyzer = LighthouseAnalyzer()
    result = analyzer.analyze(url)

    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.LIGHTHOUSE,
        score=result.score,
        metrics=result.metrics,
        raw_data=result.raw_data if result.success else {"error": result.error},
    )

    return {
        "analyzer": "lighthouse",
        "score": result.score,
        "metrics": result.metrics,
        "success": result.success,
        "error": result.error,
    }


@celery_app.task(bind=True, name="worker.tasks.run_seo_analysis")
def run_seo_analysis(self, scan_id: str, url: str) -> dict:
    """
    Run SEO analysis.
    """
    logger.info(f"Running SEO analysis for {url}")

    from analyzers.seo import SEOAnalyzer

    analyzer = SEOAnalyzer()
    result = analyzer.analyze(url)

    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.SEO,
        score=result.score,
        metrics=result.metrics,
        raw_data=result.raw_data if result.success else {"error": result.error},
    )

    return {
        "analyzer": "seo",
        "score": result.score,
        "issues_count": result.metrics.get("issues_count", 0) if result.metrics else 0,
        "success": result.success,
        "error": result.error,
    }


@celery_app.task(bind=True, name="worker.tasks.run_security_audit")
def run_security_audit(self, scan_id: str, url: str) -> dict:
    """
    Run security audit.
    """
    logger.info(f"Running security audit for {url}")

    from analyzers.security import SecurityAnalyzer

    analyzer = SecurityAnalyzer()
    result = analyzer.analyze(url)

    # Save to database
    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.SECURITY,
        score=result.score,
        metrics=result.metrics,
        raw_data=result.raw_data if result.success else {"error": result.error},
    )

    return {
        "analyzer": "security",
        "score": result.score,
        "issues_count": result.metrics.get("issues_count", 0) if result.metrics else 0,
        "success": result.success,
        "error": result.error,
    }


@celery_app.task(bind=True, name="worker.tasks.run_asset_analysis")
def run_asset_analysis(self, scan_id: str, url: str) -> dict:
    """
    Run asset/code analysis.
    """
    logger.info(f"Running asset analysis for {url}")

    from analyzers.assets import AssetAnalyzer

    analyzer = AssetAnalyzer()
    result = analyzer.analyze(url)

    # Save to database
    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.ASSETS,
        score=result.score,
        metrics=result.metrics,
        raw_data=result.raw_data if result.success else {"error": result.error},
    )

    return {
        "analyzer": "assets",
        "score": result.score,
        "issues_count": result.metrics.get("issues_count", 0) if result.metrics else 0,
        "success": result.success,
        "error": result.error,
    }


def generate_recommendations(scan_id: str) -> dict:
    """
    Generate recommendations based on all analysis results.

    TODO: Implement in Step 9 (Recommendation Engine)
    """
    logger.info(f"Generating recommendations for scan {scan_id}")

    # Placeholder - will be implemented in Step 9
    return {
        "scan_id": scan_id,
        "recommendations_count": 0,
        "status": "not_implemented",
    }


def _save_analysis_result(
    scan_id: str,
    analyzer_type: AnalyzerType,
    score: float | None,
    metrics: dict | None,
    raw_data: dict | None,
) -> None:
    """Helper to save analysis results to database."""
    from db.models import AnalysisResult

    scan_uuid = uuid.UUID(scan_id)

    with get_sync_session() as session:
        result = AnalysisResult(
            scan_id=scan_uuid,
            analyzer_type=analyzer_type,
            score=score,
            metrics=metrics,
            raw_data=raw_data,
        )
        session.add(result)
        session.commit()
