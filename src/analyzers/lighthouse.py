"""Lighthouse performance analyzer."""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from analyzers.base import AnalysisResult, BaseAnalyzer
from config import settings

logger = logging.getLogger(__name__)


class LighthouseAnalyzer(BaseAnalyzer):
    """
    Runs Google Lighthouse audits via CLI.

    Collects performance metrics:
    - Category scores: Performance, SEO, Accessibility, Best Practices
    - Core Web Vitals: LCP, FCP, CLS, TBT
    - Other metrics: Speed Index, TTI
    """

    @property
    def name(self) -> str:
        return "lighthouse"

    def analyze(self, url: str) -> AnalysisResult:
        """
        Run Lighthouse audit on the given URL.

        Args:
            url: Website URL to audit

        Returns:
            AnalysisResult with performance data
        """
        try:
            raw_data = self._run_lighthouse(url)
            score, metrics = self._extract_metrics(raw_data)

            return AnalysisResult(
                score=score,
                metrics=metrics,
                raw_data=raw_data,
                success=True,
            )

        except subprocess.TimeoutExpired:
            logger.error(f"Lighthouse timeout for {url}")
            return AnalysisResult(
                score=None,
                metrics={},
                raw_data={},
                success=False,
                error="Lighthouse audit timed out",
            )

        except Exception as e:
            logger.exception(f"Lighthouse failed for {url}: {e}")
            return AnalysisResult(
                score=None,
                metrics={},
                raw_data={},
                success=False,
                error=str(e),
            )

    def _run_lighthouse(self, url: str) -> dict:
        """
        Execute Lighthouse CLI and return JSON results.

        Args:
            url: URL to audit

        Returns:
            Lighthouse JSON output as dict
        """
        # Create temp file for output
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as f:
            output_path = f.name

        try:
            # Build Lighthouse command
            cmd = [
                "lighthouse",
                url,
                "--output=json",
                f"--output-path={output_path}",
                "--chrome-flags=--headless --no-sandbox --disable-gpu",
                "--quiet",
                # Run specific categories
                "--only-categories=performance,accessibility,best-practices,seo",
            ]

            logger.info(f"Running Lighthouse: {' '.join(cmd)}")

            # Execute Lighthouse
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.lighthouse_timeout,
            )

            if result.returncode != 0:
                logger.warning(f"Lighthouse stderr: {result.stderr}")

            # Read JSON output
            output_file = Path(output_path)
            if output_file.exists():
                with open(output_file) as f:
                    return json.load(f)
            else:
                raise RuntimeError(
                    f"Lighthouse output file not created: {result.stderr}"
                )

        finally:
            # Clean up temp file
            Path(output_path).unlink(missing_ok=True)

    def _extract_metrics(self, raw_data: dict) -> tuple[float | None, dict]:
        """
        Extract key metrics from Lighthouse JSON output.

        Args:
            raw_data: Full Lighthouse JSON output

        Returns:
            Tuple of (overall_score, metrics_dict)
        """
        metrics = {}

        # Extract category scores (0-1 scale, convert to 0-100)
        categories = raw_data.get("categories", {})

        category_scores = {}
        for cat_name in [
            "performance",
            "accessibility",
            "best-practices",
            "seo",
        ]:
            cat_data = categories.get(cat_name, {})
            score = cat_data.get("score")
            if score is not None:
                category_scores[cat_name] = round(score * 100, 1)

        metrics["category_scores"] = category_scores

        # Overall performance score
        perf_score = category_scores.get("performance")

        # Extract Core Web Vitals and other metrics
        audits = raw_data.get("audits", {})

        # Largest Contentful Paint (LCP) - in seconds
        lcp = audits.get("largest-contentful-paint", {})
        if lcp.get("numericValue"):
            metrics["lcp_ms"] = round(lcp["numericValue"], 0)
            metrics["lcp_seconds"] = round(lcp["numericValue"] / 1000, 2)
            metrics["lcp_score"] = (
                lcp.get("score", 0) * 100 if lcp.get("score") else None
            )

        # First Contentful Paint (FCP)
        fcp = audits.get("first-contentful-paint", {})
        if fcp.get("numericValue"):
            metrics["fcp_ms"] = round(fcp["numericValue"], 0)
            metrics["fcp_seconds"] = round(fcp["numericValue"] / 1000, 2)

        # Cumulative Layout Shift (CLS)
        cls = audits.get("cumulative-layout-shift", {})
        if cls.get("numericValue") is not None:
            metrics["cls"] = round(cls["numericValue"], 3)
            metrics["cls_score"] = (
                cls.get("score", 0) * 100 if cls.get("score") else None
            )

        # Total Blocking Time (TBT)
        tbt = audits.get("total-blocking-time", {})
        if tbt.get("numericValue"):
            metrics["tbt_ms"] = round(tbt["numericValue"], 0)

        # Speed Index
        si = audits.get("speed-index", {})
        if si.get("numericValue"):
            metrics["speed_index_ms"] = round(si["numericValue"], 0)
            metrics["speed_index_seconds"] = round(si["numericValue"] / 1000, 2)

        # Time to Interactive (TTI)
        tti = audits.get("interactive", {})
        if tti.get("numericValue"):
            metrics["tti_ms"] = round(tti["numericValue"], 0)
            metrics["tti_seconds"] = round(tti["numericValue"] / 1000, 2)

        # First Input Delay (FID) estimate - from max-potential-fid
        fid = audits.get("max-potential-fid", {})
        if fid.get("numericValue"):
            metrics["max_fid_ms"] = round(fid["numericValue"], 0)

        # Additional useful metrics
        # Server response time
        server_time = audits.get("server-response-time", {})
        if server_time.get("numericValue"):
            metrics["server_response_ms"] = round(server_time["numericValue"], 0)

        # Total byte weight
        byte_weight = audits.get("total-byte-weight", {})
        if byte_weight.get("numericValue"):
            metrics["total_bytes"] = round(byte_weight["numericValue"], 0)
            metrics["total_kb"] = round(byte_weight["numericValue"] / 1024, 1)
            metrics["total_mb"] = round(byte_weight["numericValue"] / (1024 * 1024), 2)

        # DOM size
        dom_size = audits.get("dom-size", {})
        if dom_size.get("numericValue"):
            metrics["dom_elements"] = int(dom_size["numericValue"])

        # Network requests
        network = audits.get("network-requests", {})
        if network.get("details", {}).get("items"):
            metrics["network_requests"] = len(network["details"]["items"])

        # Extract failed audits for recommendations
        failed_audits = []
        for audit_id, audit_data in audits.items():
            score = audit_data.get("score")
            if score is not None and score < 0.9:  # Failed or warning
                failed_audits.append(
                    {
                        "id": audit_id,
                        "title": audit_data.get("title", ""),
                        "description": audit_data.get("description", ""),
                        "score": score,
                        "display_value": audit_data.get("displayValue", ""),
                    }
                )

        metrics["failed_audits"] = failed_audits[:20]  # Limit to top 20

        return perf_score, metrics


# Convenience function for direct usage
def run_lighthouse_audit(url: str) -> AnalysisResult:
    """Run a Lighthouse audit on the given URL."""
    analyzer = LighthouseAnalyzer()
    return analyzer.analyze(url)
