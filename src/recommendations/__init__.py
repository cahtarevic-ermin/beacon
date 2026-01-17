"""Beacon recommendations package."""

from recommendations.engine import (
    RecommendationEngine,
    generate_recommendations_for_scan,
)
from recommendations.rules import ALL_RULES, Rule

__all__ = [
    "RecommendationEngine",
    "generate_recommendations_for_scan",
    "ALL_RULES",
    "Rule",
]
