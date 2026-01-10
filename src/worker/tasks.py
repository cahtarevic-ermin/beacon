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
    
    TODO: Implement in Step 5 (Lighthouse Analyzer)
    """
    logger.info(f"Running Lighthouse audit for {url}")

    # Placeholder - will be implemented in Step 5
    result = {
        "analyzer": "lighthouse",
        "score": None,
        "metrics": {},
        "status": "not_implemented",
    }

    # Save placeholder result
    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.LIGHTHOUSE,
        score=None,
        metrics={},
        raw_data={"status": "not_implemented"},
    )

    return result


@celery_app.task(bind=True, name="worker.tasks.run_seo_analysis")
def run_seo_analysis(self, scan_id: str, url: str) -> dict:
    """
    Run SEO analysis.
    
    TODO: Implement in Step 6 (SEO Analyzer)
    """
    logger.info(f"Running SEO analysis for {url}")

    # Placeholder - will be implemented in Step 6
    result = {
        "analyzer": "seo",
        "score": None,
        "metrics": {},
        "status": "not_implemented",
    }

    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.SEO,
        score=None,
        metrics={},
        raw_data={"status": "not_implemented"},
    )

    return result


@celery_app.task(bind=True, name="worker.tasks.run_security_audit")
def run_security_audit(self, scan_id: str, url: str) -> dict:
    """
    Run security audit.
    
    TODO: Implement in Step 7 (Security Analyzer)
    """
    logger.info(f"Running security audit for {url}")

    # Placeholder - will be implemented in Step 7
    result = {
        "analyzer": "security",
        "score": None,
        "metrics": {},
        "status": "not_implemented",
    }

    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.SECURITY,
        score=None,
        metrics={},
        raw_data={"status": "not_implemented"},
    )

    return result


@celery_app.task(bind=True, name="worker.tasks.run_asset_analysis")
def run_asset_analysis(self, scan_id: str, url: str) -> dict:
    """
    Run asset/code analysis.
    
    TODO: Implement in Step 8 (Asset Analyzer)
    """
    logger.info(f"Running asset analysis for {url}")

    # Placeholder - will be implemented in Step 8
    result = {
        "analyzer": "assets",
        "score": None,
        "metrics": {},
        "status": "not_implemented",
    }

    _save_analysis_result(
        scan_id=scan_id,
        analyzer_type=AnalyzerType.ASSETS,
        score=None,
        metrics={},
        raw_data={"status": "not_implemented"},
    )

    return result


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
