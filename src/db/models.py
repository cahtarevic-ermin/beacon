"""SQLAlchemy database models for Beacon."""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class ScanStatus(str, enum.Enum):
    """Status of a scan job."""

    PENDING = "pending"      # Scan queued, not yet started
    RUNNING = "running"      # Scan in progress
    COMPLETED = "completed"  # Scan finished successfully
    FAILED = "failed"        # Scan encountered an error


class AnalyzerType(str, enum.Enum):
    """Types of analyzers available."""

    LIGHTHOUSE = "lighthouse"
    SEO = "seo"
    SECURITY = "security"
    ASSETS = "assets"


class Severity(str, enum.Enum):
    """Severity levels for recommendations."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, enum.Enum):
    """Categories for recommendations."""

    PERFORMANCE = "performance"
    SEO = "seo"
    SECURITY = "security"
    ACCESSIBILITY = "accessibility"
    BEST_PRACTICES = "best_practices"
    ASSETS = "assets"


class Scan(Base):
    """
    Represents a single website scan request.
    
    A scan is the top-level entity that tracks the analysis of a URL.
    It has multiple AnalysisResults (one per analyzer) and Recommendations.
    """

    __tablename__ = "scans"

    # Primary key - using UUID for globally unique identifiers
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # The URL being scanned
    url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)

    # Current status of the scan
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Optional error message if scan failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now(timezone.utc),
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Flexible metadata storage (e.g., user agent, viewport size)
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata",  # Column name in DB (metadata_ avoids SQLAlchemy reserved name)
        JSONB,
        nullable=True,
    )

    # Relationships - lazy="selectin" means related objects are loaded efficiently
    analysis_results: Mapped[list["AnalysisResult"]] = relationship(
        back_populates="scan",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    recommendations: Mapped[list["Recommendation"]] = relationship(
        back_populates="scan",
        lazy="selectin",
        cascade="all, delete-orphan",
    )


class AnalysisResult(Base):
    """
    Stores the output of a single analyzer for a scan.
    
    Each scan will have up to 4 AnalysisResults:
    - Lighthouse (performance metrics)
    - SEO (search optimization)
    - Security (headers, SSL, vulnerabilities)
    - Assets (JS/CSS bundle analysis)
    """

    __tablename__ = "analysis_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Foreign key to parent scan
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Which analyzer produced this result
    analyzer_type: Mapped[AnalyzerType] = mapped_column(
        Enum(AnalyzerType),
        nullable=False,
    )

    # Overall score (0-100) for this analyzer
    score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Normalized/extracted metrics (quick access)
    # e.g., {"lcp": 2.5, "fcp": 1.2, "cls": 0.1} for Lighthouse
    metrics: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Full raw output from the analyzer (for debugging/detailed views)
    raw_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship back to scan
    scan: Mapped["Scan"] = relationship(back_populates="analysis_results")


class Recommendation(Base):
    """
    A single actionable recommendation generated from analysis.
    
    Recommendations are created by the Recommendation Engine after
    all analyzers complete. They provide specific advice on what to fix.
    """

    __tablename__ = "recommendations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Foreign key to parent scan
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Categorization
    category: Mapped[Category] = mapped_column(Enum(Category), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, index=True)

    # Which analyzer triggered this recommendation
    source_analyzer: Mapped[AnalyzerType] = mapped_column(
        Enum(AnalyzerType),
        nullable=False,
    )

    # Human-readable content
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    fix_suggestion: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional: link to documentation or more info
    reference_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship back to scan
    scan: Mapped["Scan"] = relationship(back_populates="recommendations")
