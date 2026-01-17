"""Code and asset analyzer."""

import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from analyzers.base import AnalysisResult, BaseAnalyzer
from config import settings

logger = logging.getLogger(__name__)


class AssetAnalyzer(BaseAnalyzer):
    """
    Analyzes JavaScript and CSS assets for optimization opportunities.

    Checks:
    - Total JS/CSS bundle sizes
    - Number of requests
    - Inline vs external scripts
    - Unminified files detection
    - Duplicate library detection
    - Largest assets identification
    """

    # Asset scoring weights (total = 100)
    WEIGHTS = {
        "js_size": 30,
        "css_size": 15,
        "request_count": 20,
        "minification": 20,
        "duplicates": 15,
    }

    # Common library patterns for duplicate detection
    LIBRARY_PATTERNS = {
        "jquery": [r"jquery[.-](\d+\.?\d*\.?\d*)", r"jquery\.min\.js"],
        "react": [r"react[.-](\d+\.?\d*\.?\d*)", r"react\.production\.min\.js"],
        "vue": [r"vue[.-](\d+\.?\d*\.?\d*)", r"vue\.min\.js"],
        "angular": [r"angular[.-](\d+\.?\d*\.?\d*)", r"angular\.min\.js"],
        "lodash": [r"lodash[.-](\d+\.?\d*\.?\d*)", r"lodash\.min\.js"],
        "moment": [r"moment[.-](\d+\.?\d*\.?\d*)", r"moment\.min\.js"],
        "bootstrap": [r"bootstrap[.-](\d+\.?\d*\.?\d*)", r"bootstrap\.min\.(js|css)"],
        "axios": [r"axios[.-](\d+\.?\d*\.?\d*)", r"axios\.min\.js"],
    }

    # Size thresholds (in bytes)
    JS_SIZE_EXCELLENT = 100 * 1024  # 100KB
    JS_SIZE_GOOD = 250 * 1024  # 250KB
    JS_SIZE_WARNING = 500 * 1024  # 500KB
    JS_SIZE_CRITICAL = 1024 * 1024  # 1MB

    CSS_SIZE_EXCELLENT = 50 * 1024  # 50KB
    CSS_SIZE_GOOD = 100 * 1024  # 100KB
    CSS_SIZE_WARNING = 200 * 1024  # 200KB

    @property
    def name(self) -> str:
        return "assets"

    def analyze(self, url: str) -> AnalysisResult:
        """
        Run asset analysis on the given URL.

        Args:
            url: Website URL to analyze

        Returns:
            AnalysisResult with asset metrics and optimization hints
        """
        try:
            # Fetch the page HTML
            html, base_url = self._fetch_page(url)
            soup = BeautifulSoup(html, "lxml")

            # Analyze scripts
            js_analysis = self._analyze_scripts(soup, base_url)

            # Analyze stylesheets
            css_analysis = self._analyze_stylesheets(soup, base_url)

            # Check for duplicates
            duplicates = self._detect_duplicates(js_analysis, css_analysis)

            # Calculate scores
            scores = self._calculate_scores(js_analysis, css_analysis, duplicates)

            # Build metrics
            metrics = {
                "score": scores["overall"],
                "js": js_analysis,
                "css": css_analysis,
                "duplicates": duplicates,
                "scores": scores,
                "summary": self._build_summary(js_analysis, css_analysis),
                "issues": self._collect_issues(
                    js_analysis, css_analysis, duplicates, scores
                ),
            }

            metrics["issues_count"] = len(metrics["issues"])

            return AnalysisResult(
                score=scores["overall"],
                metrics=metrics,
                raw_data={
                    "js_files": js_analysis.get("files", []),
                    "css_files": css_analysis.get("files", []),
                },
                success=True,
            )

        except httpx.TimeoutException:
            logger.error(f"Timeout fetching {url}")
            return AnalysisResult(
                score=None,
                metrics={},
                raw_data={},
                success=False,
                error="Timeout fetching page",
            )

        except Exception as e:
            logger.exception(f"Asset analysis failed for {url}: {e}")
            return AnalysisResult(
                score=None,
                metrics={},
                raw_data={},
                success=False,
                error=str(e),
            )

    def _fetch_page(self, url: str) -> tuple[str, str]:
        """Fetch page HTML and determine base URL."""
        with httpx.Client(
            timeout=settings.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; BeaconBot/1.0)"},
        ) as client:
            response = client.get(url)
            response.raise_for_status()

            # Determine base URL for resolving relative paths
            base_url = str(response.url)

            return response.text, base_url

    def _analyze_scripts(self, soup: BeautifulSoup, base_url: str) -> dict:
        """Analyze all JavaScript on the page."""
        result = {
            "total_size": 0,
            "total_size_kb": 0,
            "external_count": 0,
            "inline_count": 0,
            "files": [],
            "largest_files": [],
            "unminified": [],
            "async_count": 0,
            "defer_count": 0,
            "blocking_count": 0,
        }

        scripts = soup.find_all("script")

        for script in scripts:
            src = script.get("src")

            if src:
                # External script
                result["external_count"] += 1

                # Check async/defer
                if script.get("async"):
                    result["async_count"] += 1
                elif script.get("defer"):
                    result["defer_count"] += 1
                else:
                    result["blocking_count"] += 1

                # Fetch and analyze the file
                file_info = self._fetch_asset(src, base_url, "js")
                if file_info:
                    result["files"].append(file_info)
                    result["total_size"] += file_info["size"]

                    if not file_info["is_minified"]:
                        result["unminified"].append(file_info["url"])
            else:
                # Inline script
                content = script.string or ""
                if content.strip():
                    result["inline_count"] += 1
                    inline_size = len(content.encode("utf-8"))
                    result["total_size"] += inline_size

        # Sort by size and get largest
        result["files"].sort(key=lambda x: x["size"], reverse=True)
        result["largest_files"] = [
            {"url": f["url"], "size_kb": f["size_kb"]} for f in result["files"][:5]
        ]

        result["total_size_kb"] = round(result["total_size"] / 1024, 1)
        result["total_size_mb"] = round(result["total_size"] / (1024 * 1024), 2)

        return result

    def _analyze_stylesheets(self, soup: BeautifulSoup, base_url: str) -> dict:
        """Analyze all CSS on the page."""
        result = {
            "total_size": 0,
            "total_size_kb": 0,
            "external_count": 0,
            "inline_count": 0,
            "files": [],
            "largest_files": [],
            "unminified": [],
        }

        # External stylesheets
        links = soup.find_all("link", rel="stylesheet")
        for link in links:
            href = link.get("href")
            if href:
                result["external_count"] += 1
                file_info = self._fetch_asset(href, base_url, "css")
                if file_info:
                    result["files"].append(file_info)
                    result["total_size"] += file_info["size"]

                    if not file_info["is_minified"]:
                        result["unminified"].append(file_info["url"])

        # Inline styles
        styles = soup.find_all("style")
        for style in styles:
            content = style.string or ""
            if content.strip():
                result["inline_count"] += 1
                inline_size = len(content.encode("utf-8"))
                result["total_size"] += inline_size

        # Sort by size and get largest
        result["files"].sort(key=lambda x: x["size"], reverse=True)
        result["largest_files"] = [
            {"url": f["url"], "size_kb": f["size_kb"]} for f in result["files"][:5]
        ]

        result["total_size_kb"] = round(result["total_size"] / 1024, 1)
        result["total_size_mb"] = round(result["total_size"] / (1024 * 1024), 2)

        return result

    def _fetch_asset(self, url: str, base_url: str, asset_type: str) -> dict | None:
        """Fetch an asset and analyze it."""
        try:
            # Resolve relative URL
            full_url = urljoin(base_url, url)

            # Skip data URLs and blob URLs
            if full_url.startswith(("data:", "blob:")):
                return None

            with httpx.Client(
                timeout=10,
                follow_redirects=True,
            ) as client:
                response = client.get(full_url)
                response.raise_for_status()

                content = response.content
                size = len(content)

                # Check if minified
                is_minified = self._is_minified(
                    content.decode("utf-8", errors="ignore"), asset_type
                )

                return {
                    "url": full_url,
                    "filename": urlparse(full_url).path.split("/")[-1] or "unknown",
                    "size": size,
                    "size_kb": round(size / 1024, 1),
                    "is_minified": is_minified,
                    "content_type": response.headers.get("content-type", ""),
                }

        except Exception as e:
            logger.debug(f"Failed to fetch asset {url}: {e}")
            return None

    def _is_minified(self, content: str, asset_type: str) -> bool:
        """
        Heuristically detect if content is minified.

        Minified files typically have:
        - Very long lines
        - Few newlines relative to content length
        - Low whitespace ratio
        """
        if not content or len(content) < 100:
            return True  # Too small to tell, assume minified

        lines = content.split("\n")
        avg_line_length = len(content) / max(len(lines), 1)

        # If average line length is very high, likely minified
        if avg_line_length > 500:
            return True

        # Check whitespace ratio
        whitespace_count = sum(1 for c in content if c in " \t\n\r")
        whitespace_ratio = whitespace_count / len(content)

        # Minified files typically have < 5% whitespace
        if whitespace_ratio < 0.05:
            return True

        # Check for common minification patterns
        if asset_type == "js":
            # Check for lack of formatting
            if content.count(";\n") < content.count(";") * 0.1:
                return True

        return False

    def _detect_duplicates(self, js_analysis: dict, css_analysis: dict) -> dict:
        """Detect duplicate libraries."""
        result = {
            "found": [],
            "potential_savings_kb": 0,
        }

        all_files = js_analysis.get("files", []) + css_analysis.get("files", [])
        all_urls = [f["url"].lower() for f in all_files]

        library_occurrences = {}

        for library, patterns in self.LIBRARY_PATTERNS.items():
            matches = []
            for url in all_urls:
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        matches.append(url)
                        break

            if len(matches) > 1:
                library_occurrences[library] = matches

        for library, urls in library_occurrences.items():
            # Find sizes of duplicate files
            sizes = []
            for url in urls:
                for f in all_files:
                    if f["url"].lower() == url:
                        sizes.append(f["size"])
                        break

            if len(sizes) > 1:
                # Potential savings = all but the largest
                savings = sum(sorted(sizes)[:-1])
                result["found"].append(
                    {
                        "library": library,
                        "occurrences": len(urls),
                        "urls": urls,
                        "potential_savings_kb": round(savings / 1024, 1),
                    }
                )
                result["potential_savings_kb"] += round(savings / 1024, 1)

        return result

    def _calculate_scores(
        self, js_analysis: dict, css_analysis: dict, duplicates: dict
    ) -> dict:
        """Calculate scores for each category."""
        scores = {}

        # JS Size Score
        js_size = js_analysis["total_size"]
        if js_size <= self.JS_SIZE_EXCELLENT:
            scores["js_size"] = 100
        elif js_size <= self.JS_SIZE_GOOD:
            scores["js_size"] = 80
        elif js_size <= self.JS_SIZE_WARNING:
            scores["js_size"] = 60
        elif js_size <= self.JS_SIZE_CRITICAL:
            scores["js_size"] = 40
        else:
            scores["js_size"] = 20

        # CSS Size Score
        css_size = css_analysis["total_size"]
        if css_size <= self.CSS_SIZE_EXCELLENT:
            scores["css_size"] = 100
        elif css_size <= self.CSS_SIZE_GOOD:
            scores["css_size"] = 80
        elif css_size <= self.CSS_SIZE_WARNING:
            scores["css_size"] = 60
        else:
            scores["css_size"] = 40

        # Request Count Score
        total_requests = js_analysis["external_count"] + css_analysis["external_count"]
        if total_requests <= 5:
            scores["request_count"] = 100
        elif total_requests <= 10:
            scores["request_count"] = 80
        elif total_requests <= 20:
            scores["request_count"] = 60
        elif total_requests <= 30:
            scores["request_count"] = 40
        else:
            scores["request_count"] = 20

        # Minification Score
        total_files = len(js_analysis.get("files", [])) + len(
            css_analysis.get("files", [])
        )
        unminified_count = len(js_analysis.get("unminified", [])) + len(
            css_analysis.get("unminified", [])
        )

        if total_files == 0:
            scores["minification"] = 100
        else:
            minified_ratio = (total_files - unminified_count) / total_files
            scores["minification"] = round(minified_ratio * 100)

        # Duplicates Score
        duplicate_count = len(duplicates.get("found", []))
        if duplicate_count == 0:
            scores["duplicates"] = 100
        elif duplicate_count == 1:
            scores["duplicates"] = 70
        elif duplicate_count == 2:
            scores["duplicates"] = 50
        else:
            scores["duplicates"] = 30

        # Calculate overall weighted score
        overall = 0
        for category, weight in self.WEIGHTS.items():
            category_score = scores.get(category, 0)
            overall += (category_score / 100) * weight

        scores["overall"] = round(overall, 1)

        return scores

    def _build_summary(self, js_analysis: dict, css_analysis: dict) -> dict:
        """Build a summary of asset analysis."""
        return {
            "total_js_size_kb": js_analysis["total_size_kb"],
            "total_css_size_kb": css_analysis["total_size_kb"],
            "total_size_kb": round(
                js_analysis["total_size_kb"] + css_analysis["total_size_kb"], 1
            ),
            "js_files": js_analysis["external_count"],
            "css_files": css_analysis["external_count"],
            "inline_scripts": js_analysis["inline_count"],
            "inline_styles": css_analysis["inline_count"],
            "blocking_scripts": js_analysis["blocking_count"],
            "async_scripts": js_analysis["async_count"],
            "defer_scripts": js_analysis["defer_count"],
        }

    def _collect_issues(
        self,
        js_analysis: dict,
        css_analysis: dict,
        duplicates: dict,
        scores: dict,
    ) -> list[dict]:
        """Collect all issues and optimization suggestions."""
        issues = []

        # JS Size Issues
        js_size = js_analysis["total_size"]
        if js_size > self.JS_SIZE_CRITICAL:
            issues.append(
                {
                    "category": "performance",
                    "severity": "high",
                    "message": f"Total JavaScript size is {js_analysis['total_size_kb']}KB (critical: >1MB)",
                    "suggestion": "Enable code splitting, lazy load non-critical modules, remove unused code",
                }
            )
        elif js_size > self.JS_SIZE_WARNING:
            issues.append(
                {
                    "category": "performance",
                    "severity": "medium",
                    "message": f"Total JavaScript size is {js_analysis['total_size_kb']}KB (warning: >500KB)",
                    "suggestion": "Consider code splitting and tree shaking to reduce bundle size",
                }
            )

        # Largest JS files
        for file_info in js_analysis.get("largest_files", [])[:3]:
            if file_info["size_kb"] > 500:
                issues.append(
                    {
                        "category": "performance",
                        "severity": "high",
                        "message": f"Large JS file: {file_info['url'][:80]} ({file_info['size_kb']}KB)",
                        "suggestion": "Split this file into smaller chunks or lazy load",
                    }
                )

        # CSS Size Issues
        css_size = css_analysis["total_size"]
        if css_size > self.CSS_SIZE_WARNING:
            issues.append(
                {
                    "category": "performance",
                    "severity": "medium",
                    "message": f"Total CSS size is {css_analysis['total_size_kb']}KB",
                    "suggestion": "Remove unused CSS, consider CSS-in-JS or critical CSS extraction",
                }
            )

        # Blocking Scripts
        if js_analysis["blocking_count"] > 3:
            issues.append(
                {
                    "category": "performance",
                    "severity": "medium",
                    "message": f"{js_analysis['blocking_count']} render-blocking scripts found",
                    "suggestion": "Add async or defer attributes to non-critical scripts",
                }
            )

        # Unminified Files
        unminified_js = js_analysis.get("unminified", [])
        unminified_css = css_analysis.get("unminified", [])

        if unminified_js:
            issues.append(
                {
                    "category": "performance",
                    "severity": "medium",
                    "message": f"{len(unminified_js)} unminified JavaScript file(s) detected",
                    "suggestion": "Minify JavaScript files to reduce size by 30-50%",
                    "files": unminified_js[:5],
                }
            )

        if unminified_css:
            issues.append(
                {
                    "category": "performance",
                    "severity": "low",
                    "message": f"{len(unminified_css)} unminified CSS file(s) detected",
                    "suggestion": "Minify CSS files to reduce size",
                    "files": unminified_css[:5],
                }
            )

        # Duplicate Libraries
        for dup in duplicates.get("found", []):
            issues.append(
                {
                    "category": "performance",
                    "severity": "high",
                    "message": f"Duplicate library detected: {dup['library']} loaded {dup['occurrences']} times",
                    "suggestion": f"Remove duplicate {dup['library']} to save ~{dup['potential_savings_kb']}KB",
                }
            )

        # Too Many Requests
        total_requests = js_analysis["external_count"] + css_analysis["external_count"]
        if total_requests > 20:
            issues.append(
                {
                    "category": "performance",
                    "severity": "medium",
                    "message": f"High number of asset requests ({total_requests} files)",
                    "suggestion": "Bundle files together or use HTTP/2 server push",
                }
            )

        return issues


# Convenience function
def run_asset_analysis(url: str) -> AnalysisResult:
    """Run asset analysis on the given URL."""
    analyzer = AssetAnalyzer()
    return analyzer.analyze(url)
