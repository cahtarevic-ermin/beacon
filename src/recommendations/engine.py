"""Recommendation engine that aggregates analysis results and generates recommendations."""

import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AnalysisResult, AnalyzerType, Category, Recommendation, Severity
from recommendations.rules import ALL_RULES, Rule

logger = logging.getLogger(__name__)


class RecommendationEngine:
    """
    Generates recommendations by evaluating rules against analysis results.

    The engine:
    1. Loads all analysis results for a scan
    2. Builds a unified context from all analyzers
    3. Evaluates each rule against the context
    4. Creates Recommendation records for triggered rules
    5. Deduplicates and prioritizes recommendations
    """

    # Map rule categories to database Category enum
    CATEGORY_MAP = {
        "performance": Category.PERFORMANCE,
        "seo": Category.SEO,
        "security": Category.SECURITY,
        "accessibility": Category.ACCESSIBILITY,
        "assets": Category.ASSETS,
        "best_practices": Category.BEST_PRACTICES,
    }

    # Map severity strings to database Severity enum
    SEVERITY_MAP = {
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    # Map rule categories to analyzer types
    ANALYZER_MAP = {
        "performance": AnalyzerType.LIGHTHOUSE,
        "seo": AnalyzerType.SEO,
        "security": AnalyzerType.SECURITY,
        "accessibility": AnalyzerType.LIGHTHOUSE,
        "assets": AnalyzerType.ASSETS,
        "best_practices": AnalyzerType.LIGHTHOUSE,
    }

    def __init__(self, session: Session):
        """Initialize with a database session."""
        self.session = session

    def generate(self, scan_id: uuid.UUID) -> list[dict]:
        """
        Generate recommendations for a scan.

        Args:
            scan_id: UUID of the scan to generate recommendations for

        Returns:
            List of generated recommendation dicts
        """
        logger.info(f"Generating recommendations for scan {scan_id}")

        # Load analysis results
        context = self._build_context(scan_id)

        if not context:
            logger.warning(f"No analysis results found for scan {scan_id}")
            return []

        # Evaluate rules
        triggered_rules = self._evaluate_rules(context)
        logger.info(f"Triggered {len(triggered_rules)} rules")

        # Create recommendations
        recommendations = self._create_recommendations(scan_id, triggered_rules)

        return recommendations

    def _build_context(self, scan_id: uuid.UUID) -> dict:
        """
        Build a unified context from all analysis results.

        Args:
            scan_id: UUID of the scan

        Returns:
            Dict with analyzer results keyed by analyzer name
        """
        context = {}

        # Query all analysis results for this scan
        results = (
            self.session.execute(
                select(AnalysisResult).where(AnalysisResult.scan_id == scan_id)
            )
            .scalars()
            .all()
        )

        for result in results:
            analyzer_name = result.analyzer_type.value  # e.g., "lighthouse", "seo"
            context[analyzer_name] = {
                "score": result.score,
                "metrics": result.metrics or {},
                "raw_data": result.raw_data or {},
            }

        return context

    def _evaluate_rules(self, context: dict) -> list[Rule]:
        """
        Evaluate all rules against the context.

        Args:
            context: Unified context from all analyzers

        Returns:
            List of rules that were triggered
        """
        triggered = []

        for rule in ALL_RULES:
            try:
                if rule.condition(context):
                    triggered.append(rule)
                    logger.debug(f"Rule triggered: {rule.id}")
            except Exception as e:
                logger.warning(f"Error evaluating rule {rule.id}: {e}")

        # Sort by severity (high first)
        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        triggered.sort(key=lambda r: severity_order.get(r.severity, 99))

        return triggered

    def _create_recommendations(
        self,
        scan_id: uuid.UUID,
        triggered_rules: list[Rule],
    ) -> list[dict]:
        """
        Create Recommendation records for triggered rules.

        Args:
            scan_id: UUID of the scan
            triggered_rules: List of triggered rules

        Returns:
            List of created recommendation dicts
        """
        recommendations = []
        seen_ids = set()

        for rule in triggered_rules:
            # Skip duplicates (same rule ID)
            if rule.id in seen_ids:
                continue
            seen_ids.add(rule.id)

            # Map to database enums
            category = self.CATEGORY_MAP.get(rule.category, Category.PERFORMANCE)
            severity = self.SEVERITY_MAP.get(rule.severity, Severity.MEDIUM)
            source_analyzer = self.ANALYZER_MAP.get(
                rule.category, AnalyzerType.LIGHTHOUSE
            )

            # Create database record
            recommendation = Recommendation(
                scan_id=scan_id,
                category=category,
                severity=severity,
                source_analyzer=source_analyzer,
                title=rule.title,
                description=rule.description,
                fix_suggestion=rule.fix_suggestion,
                reference_url=rule.reference_url,
            )

            self.session.add(recommendation)

            # Build response dict
            recommendations.append(
                {
                    "id": str(recommendation.id),
                    "category": rule.category,
                    "severity": rule.severity,
                    "title": rule.title,
                    "description": rule.description,
                    "fix_suggestion": rule.fix_suggestion,
                    "reference_url": rule.reference_url,
                }
            )

        # Commit all recommendations
        self.session.commit()

        logger.info(
            f"Created {len(recommendations)} recommendations for scan {scan_id}"
        )

        return recommendations


def generate_recommendations_for_scan(
    session: Session, scan_id: uuid.UUID
) -> list[dict]:
    """
    Convenience function to generate recommendations for a scan.

    Args:
        session: Database session
        scan_id: UUID of the scan

    Returns:
        List of generated recommendation dicts
    """
    engine = RecommendationEngine(session)
    return engine.generate(scan_id)
