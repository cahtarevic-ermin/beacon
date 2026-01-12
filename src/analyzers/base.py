"""Base analyzer interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AnalysisResult:
    """Standard result format for all analyzers."""

    score: float | None  # Overall score (0-100)
    metrics: dict  # Key metrics extracted
    raw_data: dict  # Full raw output for debugging
    success: bool  # Whether analysis completed successfully
    error: str | None = None  # Error message if failed


class BaseAnalyzer(ABC):
    """Abstract base class for all analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return analyzer name."""
        pass

    @abstractmethod
    def analyze(self, url: str) -> AnalysisResult:
        """
        Run analysis on the given URL.

        Args:
            url: The website URL to analyze

        Returns:
            AnalysisResult with scores, metrics, and raw data
        """
        pass
