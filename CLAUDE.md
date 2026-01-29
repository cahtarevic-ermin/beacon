# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Beacon is a website analysis engine that performs automated audits across performance, SEO, security, and accessibility dimensions. It's a FastAPI-based REST API with Celery background workers for async analysis.

## Development Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Start infrastructure (PostgreSQL 16, Redis 7)
docker-compose up -d

# Run API server
uvicorn src.main:app --reload

# Run Celery worker
celery -A src.worker.celery_app worker --loglevel=info

# Linting and formatting
ruff check .
ruff format .

# Type checking
mypy src/

# Run tests
pytest
pytest --cov=src  # with coverage
pytest tests/path/to/test.py::test_function  # single test

# Database migrations
alembic upgrade head
alembic revision --autogenerate -m "description"
```

## Architecture

**Request Flow:**
```
POST /api/v1/scans → Scan created (PENDING) → Celery task dispatched
                                                    ↓
                            Analyzers run in parallel (chord pattern)
                                                    ↓
                            Results saved → RecommendationEngine runs
                                                    ↓
                            Scan marked COMPLETED → Client polls for results
```

**Core Modules:**

- **`src/api/`**: FastAPI routes and Pydantic schemas. Endpoints at `/api/v1/scans`.
- **`src/analyzers/`**: Plugin-style analyzers extending `BaseAnalyzer`. Each returns normalized `AnalysisResult` with score, metrics, raw_data fields.
- **`src/db/`**: SQLAlchemy async models (`Scan`, `AnalysisResult`, `Recommendation`) and repository pattern for data access.
- **`src/recommendations/`**: Rule-based engine with 50+ rules in `rules.py`. Evaluates analysis results and generates prioritized recommendations.
- **`src/worker/`**: Celery tasks using chords for parallel analyzer execution followed by `finalize_scan()`.

**Key Patterns:**

- Abstract `BaseAnalyzer` class defines the analyzer contract - new analyzers implement `analyze(url) -> AnalysisResult`
- Repository pattern (`ScanRepository`, `AnalysisResultRepository`, `RecommendationRepository`) for all database operations
- Celery uses sync SQLAlchemy (separate engine) due to async limitations; API uses async throughout
- UUIDs for primary keys, JSONB for flexible metric storage, cascade deletes on relationships

## Code Style

- Python 3.10+, strict mypy, ruff for linting
- 100 character line length
- Full type annotations required
- All analyzers must return `AnalysisResult` dataclass with success/error handling
