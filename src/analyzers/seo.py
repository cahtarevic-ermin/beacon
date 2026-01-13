"""SEO analysis engine."""

import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from analyzers.base import AnalysisResult, BaseAnalyzer
from config import settings

logger = logging.getLogger(__name__)


class SEOAnalyzer(BaseAnalyzer):
    """
    Analyzes HTML for SEO best practices.

    Checks:
    - Title tag (existence, length)
    - Meta description (existence, length)
    - Canonical URL
    - H1 headings (existence, count)
    - Image alt attributes
    - Open Graph / Twitter Card tags
    - Robots meta tag
    - Structured data (JSON-LD)
    """

    # SEO scoring weights (total = 100)
    WEIGHTS = {
        "title": 20,
        "meta_description": 15,
        "h1": 15,
        "canonical": 10,
        "alt_tags": 15,
        "open_graph": 10,
        "robots": 5,
        "structured_data": 10,
    }

    @property
    def name(self) -> str:
        return "seo"

    def analyze(self, url: str) -> AnalysisResult:
        """
        Run SEO analysis on the given URL.

        Args:
            url: Website URL to analyze

        Returns:
            AnalysisResult with SEO scores and issues
        """
        try:
            # Fetch the page HTML
            html, response_headers = self._fetch_page(url)
            soup = BeautifulSoup(html, "lxml")

            # Run all checks
            checks = {
                "title": self._check_title(soup),
                "meta_description": self._check_meta_description(soup),
                "h1": self._check_h1(soup),
                "canonical": self._check_canonical(soup, url),
                "alt_tags": self._check_alt_tags(soup),
                "open_graph": self._check_open_graph(soup),
                "robots": self._check_robots(soup, response_headers),
                "structured_data": self._check_structured_data(soup),
            }

            # Additional checks (not scored, but useful info)
            extra_info = {
                "headings": self._analyze_heading_structure(soup),
                "links": self._analyze_links(soup, url),
                "meta_tags": self._get_all_meta_tags(soup),
            }

            # Calculate overall score
            score = self._calculate_score(checks)

            # Build metrics
            metrics = {
                "score": score,
                "checks": checks,
                **extra_info,
            }

            # Collect issues
            issues = self._collect_issues(checks)
            metrics["issues"] = issues
            metrics["issues_count"] = len(issues)

            return AnalysisResult(
                score=score,
                metrics=metrics,
                raw_data={"html_length": len(html), "checks": checks},
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
            logger.exception(f"SEO analysis failed for {url}: {e}")
            return AnalysisResult(
                score=None,
                metrics={},
                raw_data={},
                success=False,
                error=str(e),
            )

    def _fetch_page(self, url: str) -> tuple[str, dict]:
        """Fetch page HTML and headers."""
        with httpx.Client(
            timeout=settings.http_timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; BeaconBot/1.0; +https://example.com/bot)"
            },
        ) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.text, dict(response.headers)

    def _check_title(self, soup: BeautifulSoup) -> dict:
        """Check title tag."""
        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else None

        result = {
            "exists": title is not None,
            "value": title,
            "length": len(title) if title else 0,
            "score": 0,
            "issues": [],
        }

        if not title:
            result["issues"].append("Missing title tag")
        elif len(title) < 30:
            result["issues"].append(
                f"Title too short ({len(title)} chars, recommend 50-60)"
            )
            result["score"] = 50
        elif len(title) > 60:
            result["issues"].append(
                f"Title too long ({len(title)} chars, recommend 50-60)"
            )
            result["score"] = 70
        else:
            result["score"] = 100

        return result

    def _check_meta_description(self, soup: BeautifulSoup) -> dict:
        """Check meta description."""
        meta_desc = soup.find("meta", attrs={"name": "description"})
        description = meta_desc.get("content", "").strip() if meta_desc else None

        result = {
            "exists": description is not None and len(description) > 0,
            "value": description,
            "length": len(description) if description else 0,
            "score": 0,
            "issues": [],
        }

        if not description:
            result["issues"].append("Missing meta description")
        elif len(description) < 120:
            result["issues"].append(
                f"Meta description too short ({len(description)} chars, recommend 150-160)"
            )
            result["score"] = 50
        elif len(description) > 160:
            result["issues"].append(
                f"Meta description too long ({len(description)} chars, recommend 150-160)"
            )
            result["score"] = 70
        else:
            result["score"] = 100

        return result

    def _check_h1(self, soup: BeautifulSoup) -> dict:
        """Check H1 headings."""
        h1_tags = soup.find_all("h1")
        h1_texts = [h1.get_text(strip=True) for h1 in h1_tags]

        result = {
            "count": len(h1_tags),
            "values": h1_texts[:5],  # First 5 H1s
            "score": 0,
            "issues": [],
        }

        if len(h1_tags) == 0:
            result["issues"].append("Missing H1 heading")
        elif len(h1_tags) > 1:
            result["issues"].append(
                f"Multiple H1 tags found ({len(h1_tags)}), recommend single H1"
            )
            result["score"] = 70
        else:
            if len(h1_texts[0]) < 20:
                result["issues"].append("H1 is very short")
                result["score"] = 80
            else:
                result["score"] = 100

        return result

    def _check_canonical(self, soup: BeautifulSoup, page_url: str) -> dict:
        """Check canonical URL."""
        canonical = soup.find("link", attrs={"rel": "canonical"})
        canonical_url = canonical.get("href", "").strip() if canonical else None

        result = {
            "exists": canonical_url is not None,
            "value": canonical_url,
            "matches_page": False,
            "score": 0,
            "issues": [],
        }

        if not canonical_url:
            result["issues"].append("Missing canonical URL")
        else:
            # Check if canonical matches the page URL (normalize both)
            page_parsed = urlparse(page_url)
            canonical_parsed = urlparse(canonical_url)
            result["matches_page"] = (
                page_parsed.netloc == canonical_parsed.netloc
                and page_parsed.path.rstrip("/") == canonical_parsed.path.rstrip("/")
            )
            result["score"] = 100

        return result

    def _check_alt_tags(self, soup: BeautifulSoup) -> dict:
        """Check image alt attributes."""
        images = soup.find_all("img")
        total = len(images)
        missing_alt = []
        empty_alt = []

        for img in images:
            src = img.get("src", "unknown")
            alt = img.get("alt")

            if alt is None:
                missing_alt.append(src[:100])  # Truncate long URLs
            elif alt.strip() == "":
                empty_alt.append(src[:100])

        with_alt = total - len(missing_alt) - len(empty_alt)

        result = {
            "total_images": total,
            "with_alt": with_alt,
            "missing_alt": len(missing_alt),
            "empty_alt": len(empty_alt),
            "missing_alt_samples": missing_alt[:5],
            "score": 0,
            "issues": [],
        }

        if total == 0:
            result["score"] = 100  # No images, no problem
        else:
            alt_percentage = (with_alt / total) * 100
            result["alt_percentage"] = round(alt_percentage, 1)

            if len(missing_alt) > 0:
                result["issues"].append(
                    f"{len(missing_alt)} images missing alt attribute"
                )
            if len(empty_alt) > 0:
                result["issues"].append(
                    f"{len(empty_alt)} images have empty alt attribute"
                )

            result["score"] = round(alt_percentage)

        return result

    def _check_open_graph(self, soup: BeautifulSoup) -> dict:
        """Check Open Graph and Twitter Card tags."""
        og_tags = {}
        twitter_tags = {}

        for meta in soup.find_all("meta"):
            prop = meta.get("property", "")
            name = meta.get("name", "")
            content = meta.get("content", "")

            if prop.startswith("og:"):
                og_tags[prop] = content
            elif name.startswith("twitter:"):
                twitter_tags[name] = content

        required_og = ["og:title", "og:description", "og:image", "og:url"]
        missing_og = [tag for tag in required_og if tag not in og_tags]

        result = {
            "og_tags": og_tags,
            "twitter_tags": twitter_tags,
            "has_og": len(og_tags) > 0,
            "has_twitter": len(twitter_tags) > 0,
            "missing_og": missing_og,
            "score": 0,
            "issues": [],
        }

        if not og_tags:
            result["issues"].append("Missing Open Graph tags")
        elif missing_og:
            result["issues"].append(f"Missing OG tags: {', '.join(missing_og)}")
            result["score"] = 50

        if og_tags and not missing_og:
            result["score"] = 100
        elif og_tags:
            result["score"] = 70

        return result

    def _check_robots(self, soup: BeautifulSoup, headers: dict) -> dict:
        """Check robots meta tag and X-Robots-Tag header."""
        robots_meta = soup.find("meta", attrs={"name": "robots"})
        robots_content = robots_meta.get("content", "").lower() if robots_meta else None

        x_robots = headers.get("x-robots-tag", "").lower()

        result = {
            "meta_robots": robots_content,
            "x_robots_tag": x_robots if x_robots else None,
            "is_indexable": True,
            "is_followable": True,
            "score": 100,
            "issues": [],
        }

        # Check for noindex/nofollow
        all_robots = f"{robots_content or ''} {x_robots}"
        if "noindex" in all_robots:
            result["is_indexable"] = False
            result["issues"].append("Page is set to noindex")
        if "nofollow" in all_robots:
            result["is_followable"] = False
            result["issues"].append("Page is set to nofollow")

        return result

    def _check_structured_data(self, soup: BeautifulSoup) -> dict:
        """Check for structured data (JSON-LD)."""
        json_ld_scripts = soup.find_all("script", attrs={"type": "application/ld+json"})

        result = {
            "has_json_ld": len(json_ld_scripts) > 0,
            "json_ld_count": len(json_ld_scripts),
            "types": [],
            "score": 0,
            "issues": [],
        }

        if not json_ld_scripts:
            result["issues"].append("No structured data (JSON-LD) found")
        else:
            # Try to extract @type from each script
            import json

            for script in json_ld_scripts:
                try:
                    data = json.loads(script.string)
                    if isinstance(data, dict) and "@type" in data:
                        result["types"].append(data["@type"])
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and "@type" in item:
                                result["types"].append(item["@type"])
                except (json.JSONDecodeError, TypeError):
                    pass

            result["score"] = 100

        return result

    def _analyze_heading_structure(self, soup: BeautifulSoup) -> dict:
        """Analyze heading hierarchy."""
        headings = {"h1": 0, "h2": 0, "h3": 0, "h4": 0, "h5": 0, "h6": 0}

        for level in headings:
            headings[level] = len(soup.find_all(level))

        return {
            "counts": headings,
            "total": sum(headings.values()),
        }

    def _analyze_links(self, soup: BeautifulSoup, page_url: str) -> dict:
        """Analyze internal and external links."""
        links = soup.find_all("a", href=True)
        page_domain = urlparse(page_url).netloc

        internal = 0
        external = 0
        nofollow = 0

        for link in links:
            href = link.get("href", "")
            rel = link.get("rel", [])

            # Resolve relative URLs
            full_url = urljoin(page_url, href)
            link_domain = urlparse(full_url).netloc

            if link_domain == page_domain:
                internal += 1
            elif link_domain:
                external += 1

            if "nofollow" in rel:
                nofollow += 1

        return {
            "total": len(links),
            "internal": internal,
            "external": external,
            "nofollow": nofollow,
        }

    def _get_all_meta_tags(self, soup: BeautifulSoup) -> dict:
        """Get all meta tags for reference."""
        meta_tags = {}

        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
            content = meta.get("content", "")
            if name:
                meta_tags[name] = content[:200]  # Truncate long content

        return meta_tags

    def _calculate_score(self, checks: dict) -> float:
        """Calculate weighted overall SEO score."""
        total_score = 0

        for check_name, weight in self.WEIGHTS.items():
            check_result = checks.get(check_name, {})
            check_score = check_result.get("score", 0)
            total_score += (check_score / 100) * weight

        return round(total_score, 1)

    def _collect_issues(self, checks: dict) -> list[dict]:
        """Collect all issues from checks."""
        issues = []

        severity_map = {
            "title": "high",
            "meta_description": "high",
            "h1": "medium",
            "canonical": "medium",
            "alt_tags": "medium",
            "open_graph": "low",
            "robots": "high",
            "structured_data": "low",
        }

        for check_name, check_result in checks.items():
            for issue in check_result.get("issues", []):
                issues.append(
                    {
                        "check": check_name,
                        "message": issue,
                        "severity": severity_map.get(check_name, "low"),
                    }
                )

        return issues


# Convenience function
def run_seo_analysis(url: str) -> AnalysisResult:
    """Run SEO analysis on the given URL."""
    analyzer = SEOAnalyzer()
    return analyzer.analyze(url)
