"""Recommendation rules definition."""

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class Rule:
    """A single recommendation rule."""

    id: str
    category: str  # performance, seo, security, accessibility, assets
    severity: str  # high, medium, low, info
    title: str
    description: str
    fix_suggestion: str
    condition: Callable[[dict], bool]
    reference_url: str | None = None


def _get_nested(data: dict, path: str, default: Any = None) -> Any:
    """Get a nested value from a dict using dot notation."""
    keys = path.split(".")
    value = data
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key, default)
        else:
            return default
    return value


# =============================================================================
# Performance Rules (from Lighthouse)
# =============================================================================

PERFORMANCE_RULES = [
    Rule(
        id="slow-lcp",
        category="performance",
        severity="high",
        title="Slow Largest Contentful Paint (LCP)",
        description="LCP measures when the largest content element becomes visible. Your LCP is above 2.5 seconds, which is considered slow.",
        fix_suggestion="Optimize images, preload critical resources, reduce server response time, and remove render-blocking resources.",
        condition=lambda ctx: (_get_nested(ctx, "lighthouse.metrics.lcp_seconds") or 0)
        > 2.5,
        reference_url="https://web.dev/lcp/",
    ),
    Rule(
        id="high-cls",
        category="performance",
        severity="high",
        title="High Cumulative Layout Shift (CLS)",
        description="CLS measures visual stability. A score above 0.1 indicates significant layout shifts that can frustrate users.",
        fix_suggestion="Set explicit dimensions on images/videos, avoid inserting content above existing content, and use transform animations instead of layout-triggering properties.",
        condition=lambda ctx: (_get_nested(ctx, "lighthouse.metrics.cls") or 0) > 0.1,
        reference_url="https://web.dev/cls/",
    ),
    Rule(
        id="slow-fcp",
        category="performance",
        severity="medium",
        title="Slow First Contentful Paint (FCP)",
        description="FCP measures when the first content is painted. Your FCP is above 1.8 seconds.",
        fix_suggestion="Reduce server response time, eliminate render-blocking resources, and preload critical fonts.",
        condition=lambda ctx: (_get_nested(ctx, "lighthouse.metrics.fcp_seconds") or 0)
        > 1.8,
        reference_url="https://web.dev/fcp/",
    ),
    Rule(
        id="high-tbt",
        category="performance",
        severity="high",
        title="High Total Blocking Time (TBT)",
        description="TBT measures the total time the main thread was blocked. A TBT above 200ms indicates heavy JavaScript execution.",
        fix_suggestion="Break up long tasks, reduce JavaScript execution time, and use web workers for heavy computations.",
        condition=lambda ctx: (_get_nested(ctx, "lighthouse.metrics.tbt_ms") or 0)
        > 200,
        reference_url="https://web.dev/tbt/",
    ),
    Rule(
        id="slow-tti",
        category="performance",
        severity="medium",
        title="Slow Time to Interactive (TTI)",
        description="TTI measures when the page becomes fully interactive. Your TTI is above 3.8 seconds.",
        fix_suggestion="Minimize main thread work, reduce JavaScript payload, and defer non-critical JavaScript.",
        condition=lambda ctx: (_get_nested(ctx, "lighthouse.metrics.tti_seconds") or 0)
        > 3.8,
        reference_url="https://web.dev/tti/",
    ),
    Rule(
        id="low-performance-score",
        category="performance",
        severity="high",
        title="Low Overall Performance Score",
        description="Your Lighthouse performance score is below 50, indicating significant performance issues.",
        fix_suggestion="Address the specific issues identified in the Lighthouse report, focusing on Core Web Vitals.",
        condition=lambda ctx: (
            _get_nested(ctx, "lighthouse.metrics.category_scores.performance") or 100
        )
        < 50,
        reference_url="https://web.dev/performance-scoring/",
    ),
    Rule(
        id="large-dom",
        category="performance",
        severity="medium",
        title="Large DOM Size",
        description="Your page has a large DOM with many elements, which can slow down rendering and interactivity.",
        fix_suggestion="Simplify your page structure, use virtual scrolling for long lists, and remove unnecessary wrapper elements.",
        condition=lambda ctx: (_get_nested(ctx, "lighthouse.metrics.dom_elements") or 0)
        > 1500,
        reference_url="https://developer.chrome.com/docs/lighthouse/performance/dom-size/",
    ),
]

# =============================================================================
# SEO Rules
# =============================================================================

SEO_RULES = [
    Rule(
        id="missing-title",
        category="seo",
        severity="high",
        title="Missing Page Title",
        description="Your page is missing a title tag, which is critical for SEO and user experience.",
        fix_suggestion="Add a unique, descriptive <title> tag between 50-60 characters that includes your target keywords.",
        condition=lambda ctx: not _get_nested(
            ctx, "seo.metrics.checks.title.exists", True
        ),
    ),
    Rule(
        id="title-too-short",
        category="seo",
        severity="medium",
        title="Page Title Too Short",
        description="Your page title is shorter than 30 characters, which may not be descriptive enough.",
        fix_suggestion="Expand your title to 50-60 characters to better describe your page content.",
        condition=lambda ctx: (
            _get_nested(ctx, "seo.metrics.checks.title.exists", False)
            and (_get_nested(ctx, "seo.metrics.checks.title.length") or 60) < 30
        ),
    ),
    Rule(
        id="title-too-long",
        category="seo",
        severity="low",
        title="Page Title Too Long",
        description="Your page title exceeds 60 characters and may be truncated in search results.",
        fix_suggestion="Shorten your title to 50-60 characters while keeping it descriptive.",
        condition=lambda ctx: (_get_nested(ctx, "seo.metrics.checks.title.length") or 0)
        > 60,
    ),
    Rule(
        id="missing-meta-description",
        category="seo",
        severity="high",
        title="Missing Meta Description",
        description="Your page is missing a meta description, which is important for search result snippets.",
        fix_suggestion="Add a compelling meta description of 150-160 characters that summarizes the page content.",
        condition=lambda ctx: not _get_nested(
            ctx, "seo.metrics.checks.meta_description.exists", True
        ),
    ),
    Rule(
        id="missing-h1",
        category="seo",
        severity="medium",
        title="Missing H1 Heading",
        description="Your page is missing an H1 heading, which helps search engines understand the main topic.",
        fix_suggestion="Add a single, descriptive H1 heading at the top of your main content.",
        condition=lambda ctx: (_get_nested(ctx, "seo.metrics.checks.h1.count") or 0)
        == 0,
    ),
    Rule(
        id="multiple-h1",
        category="seo",
        severity="low",
        title="Multiple H1 Headings",
        description="Your page has multiple H1 headings. While not strictly wrong, a single H1 is best practice.",
        fix_suggestion="Use only one H1 for the main topic and use H2-H6 for subtopics.",
        condition=lambda ctx: (_get_nested(ctx, "seo.metrics.checks.h1.count") or 0)
        > 1,
    ),
    Rule(
        id="missing-canonical",
        category="seo",
        severity="medium",
        title="Missing Canonical URL",
        description="Your page doesn't specify a canonical URL, which can lead to duplicate content issues.",
        fix_suggestion="Add a canonical link tag pointing to the preferred URL for this content.",
        condition=lambda ctx: not _get_nested(
            ctx, "seo.metrics.checks.canonical.exists", True
        ),
    ),
    Rule(
        id="missing-alt-tags",
        category="seo",
        severity="medium",
        title="Images Missing Alt Attributes",
        description="Some images are missing alt attributes, which hurts accessibility and image SEO.",
        fix_suggestion="Add descriptive alt text to all images that convey meaning.",
        condition=lambda ctx: (
            _get_nested(ctx, "seo.metrics.checks.alt_tags.missing_alt") or 0
        )
        > 0,
    ),
    Rule(
        id="missing-open-graph",
        category="seo",
        severity="low",
        title="Missing Open Graph Tags",
        description="Your page is missing Open Graph tags, which affects how it appears when shared on social media.",
        fix_suggestion="Add og:title, og:description, og:image, and og:url meta tags.",
        condition=lambda ctx: not _get_nested(
            ctx, "seo.metrics.checks.open_graph.has_og", True
        ),
    ),
    Rule(
        id="missing-structured-data",
        category="seo",
        severity="low",
        title="No Structured Data Found",
        description="Your page doesn't have any structured data (JSON-LD), missing opportunities for rich search results.",
        fix_suggestion="Add relevant schema.org structured data in JSON-LD format.",
        condition=lambda ctx: not _get_nested(
            ctx, "seo.metrics.checks.structured_data.has_json_ld", True
        ),
        reference_url="https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data",
    ),
    Rule(
        id="low-seo-score",
        category="seo",
        severity="high",
        title="Low SEO Score",
        description="Your overall SEO score is below 50, indicating significant SEO issues.",
        fix_suggestion="Address the specific SEO issues identified in the audit.",
        condition=lambda ctx: (_get_nested(ctx, "seo.score") or 100) < 50,
    ),
]

# =============================================================================
# Security Rules
# =============================================================================

SECURITY_RULES = [
    Rule(
        id="no-https",
        category="security",
        severity="high",
        title="Site Not Using HTTPS",
        description="Your site is not using HTTPS, which exposes users to security risks and hurts SEO.",
        fix_suggestion="Install an SSL certificate and configure your server to use HTTPS. Consider using Let's Encrypt for free certificates.",
        condition=lambda ctx: not _get_nested(
            ctx, "security.metrics.checks.https.uses_https", True
        ),
        reference_url="https://web.dev/why-https-matters/",
    ),
    Rule(
        id="ssl-expiring-soon",
        category="security",
        severity="high",
        title="SSL Certificate Expiring Soon",
        description="Your SSL certificate will expire within 30 days.",
        fix_suggestion="Renew your SSL certificate immediately to prevent security warnings.",
        condition=lambda ctx: (
            0
            < (
                _get_nested(
                    ctx, "security.metrics.checks.ssl_certificate.days_until_expiry"
                )
                or 999
            )
            < 30
        ),
    ),
    Rule(
        id="missing-hsts",
        category="security",
        severity="high",
        title="Missing HSTS Header",
        description="Your site is missing the Strict-Transport-Security header, which helps prevent downgrade attacks.",
        fix_suggestion="Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        condition=lambda ctx: "HSTS"
        in _get_nested(ctx, "security.metrics.checks.security_headers.missing", []),
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    Rule(
        id="missing-csp",
        category="security",
        severity="high",
        title="Missing Content Security Policy",
        description="Your site is missing a Content-Security-Policy header, which helps prevent XSS attacks.",
        fix_suggestion="Implement a Content Security Policy that restricts resource loading to trusted sources.",
        condition=lambda ctx: "CSP"
        in _get_nested(ctx, "security.metrics.checks.security_headers.missing", []),
        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    ),
    Rule(
        id="missing-x-frame-options",
        category="security",
        severity="medium",
        title="Missing X-Frame-Options Header",
        description="Your site is missing the X-Frame-Options header, which helps prevent clickjacking attacks.",
        fix_suggestion="Add the header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
        condition=lambda ctx: "X-Frame-Options"
        in _get_nested(ctx, "security.metrics.checks.security_headers.missing", []),
    ),
    Rule(
        id="missing-x-content-type-options",
        category="security",
        severity="medium",
        title="Missing X-Content-Type-Options Header",
        description="Your site is missing the X-Content-Type-Options header, which prevents MIME type sniffing.",
        fix_suggestion="Add the header: X-Content-Type-Options: nosniff",
        condition=lambda ctx: "X-Content-Type-Options"
        in _get_nested(ctx, "security.metrics.checks.security_headers.missing", []),
    ),
    Rule(
        id="server-version-disclosed",
        category="security",
        severity="low",
        title="Server Version Disclosed",
        description="Your server is disclosing version information, which could help attackers target known vulnerabilities.",
        fix_suggestion="Configure your server to hide version information in the Server header.",
        condition=lambda ctx: _get_nested(
            ctx,
            "security.metrics.checks.information_disclosure.version_disclosed",
            False,
        ),
    ),
    Rule(
        id="exposed-admin-panel",
        category="security",
        severity="high",
        title="Exposed Admin Panel",
        description="Common admin paths are accessible on your server.",
        fix_suggestion="Restrict access to admin panels using IP whitelisting, VPN, or strong authentication.",
        condition=lambda ctx: len(
            _get_nested(ctx, "security.metrics.checks.admin_exposure.exposed_paths", [])
        )
        > 0,
    ),
    Rule(
        id="low-security-score",
        category="security",
        severity="high",
        title="Low Security Score",
        description="Your overall security score is below 50, indicating significant security concerns.",
        fix_suggestion="Address the specific security issues identified in the audit, prioritizing high-severity items.",
        condition=lambda ctx: (_get_nested(ctx, "security.score") or 100) < 50,
    ),
]

# =============================================================================
# Accessibility Rules (from Lighthouse)
# =============================================================================

ACCESSIBILITY_RULES = [
    Rule(
        id="low-accessibility-score",
        category="accessibility",
        severity="high",
        title="Low Accessibility Score",
        description="Your Lighthouse accessibility score is below 70, indicating significant accessibility issues.",
        fix_suggestion="Review the accessibility audit results and fix issues related to color contrast, labels, ARIA, and keyboard navigation.",
        condition=lambda ctx: (
            _get_nested(ctx, "lighthouse.metrics.category_scores.accessibility") or 100
        )
        < 70,
        reference_url="https://web.dev/accessibility-scoring/",
    ),
    Rule(
        id="poor-accessibility",
        category="accessibility",
        severity="medium",
        title="Accessibility Needs Improvement",
        description="Your accessibility score is between 70-90. There's room for improvement.",
        fix_suggestion="Review failed accessibility audits in Lighthouse and address remaining issues.",
        condition=lambda ctx: 70
        <= (_get_nested(ctx, "lighthouse.metrics.category_scores.accessibility") or 100)
        < 90,
    ),
]

# =============================================================================
# Asset/Bundle Rules
# =============================================================================

ASSET_RULES = [
    Rule(
        id="large-js-bundle",
        category="assets",
        severity="high",
        title="Large JavaScript Bundle",
        description="Your total JavaScript size exceeds 500KB, which significantly impacts load time.",
        fix_suggestion="Enable code splitting, lazy load non-critical modules, remove unused code, and use tree shaking.",
        condition=lambda ctx: (_get_nested(ctx, "assets.metrics.js.total_size_kb") or 0)
        > 500,
    ),
    Rule(
        id="critical-js-bundle",
        category="assets",
        severity="high",
        title="Critical JavaScript Bundle Size",
        description="Your total JavaScript size exceeds 1MB, causing severe performance issues.",
        fix_suggestion="Immediately audit your JavaScript dependencies, remove unused packages, and implement aggressive code splitting.",
        condition=lambda ctx: (_get_nested(ctx, "assets.metrics.js.total_size_kb") or 0)
        > 1000,
    ),
    Rule(
        id="large-css-bundle",
        category="assets",
        severity="medium",
        title="Large CSS Bundle",
        description="Your total CSS size exceeds 200KB.",
        fix_suggestion="Remove unused CSS, consider CSS-in-JS or critical CSS extraction, and split CSS by route.",
        condition=lambda ctx: (
            _get_nested(ctx, "assets.metrics.css.total_size_kb") or 0
        )
        > 200,
    ),
    Rule(
        id="many-render-blocking-scripts",
        category="assets",
        severity="medium",
        title="Many Render-Blocking Scripts",
        description="You have more than 3 render-blocking scripts, delaying page rendering.",
        fix_suggestion="Add async or defer attributes to non-critical scripts, or move them to the end of the body.",
        condition=lambda ctx: (
            _get_nested(ctx, "assets.metrics.js.blocking_count") or 0
        )
        > 3,
    ),
    Rule(
        id="unminified-js",
        category="assets",
        severity="medium",
        title="Unminified JavaScript Files",
        description="Some JavaScript files appear to be unminified, increasing file size by 30-50%.",
        fix_suggestion="Minify all JavaScript files using a build tool like webpack, esbuild, or terser.",
        condition=lambda ctx: len(_get_nested(ctx, "assets.metrics.js.unminified", []))
        > 0,
    ),
    Rule(
        id="unminified-css",
        category="assets",
        severity="low",
        title="Unminified CSS Files",
        description="Some CSS files appear to be unminified.",
        fix_suggestion="Minify all CSS files using a tool like cssnano or clean-css.",
        condition=lambda ctx: len(_get_nested(ctx, "assets.metrics.css.unminified", []))
        > 0,
    ),
    Rule(
        id="duplicate-libraries",
        category="assets",
        severity="high",
        title="Duplicate Libraries Detected",
        description="The same library appears to be loaded multiple times.",
        fix_suggestion="Remove duplicate library imports and ensure each library is loaded only once.",
        condition=lambda ctx: len(
            _get_nested(ctx, "assets.metrics.duplicates.found", [])
        )
        > 0,
    ),
    Rule(
        id="too-many-requests",
        category="assets",
        severity="medium",
        title="Too Many Asset Requests",
        description="Your page makes more than 20 requests for CSS/JS files.",
        fix_suggestion="Bundle files together, use HTTP/2 multiplexing, or implement resource hints like preload.",
        condition=lambda ctx: (
            (_get_nested(ctx, "assets.metrics.js.external_count") or 0)
            + (_get_nested(ctx, "assets.metrics.css.external_count") or 0)
        )
        > 20,
    ),
    Rule(
        id="low-assets-score",
        category="assets",
        severity="high",
        title="Low Assets Score",
        description="Your overall assets score is below 50, indicating significant optimization opportunities.",
        fix_suggestion="Address the specific asset issues identified in the audit.",
        condition=lambda ctx: (_get_nested(ctx, "assets.score") or 100) < 50,
    ),
]

# =============================================================================
# Best Practices Rules (from Lighthouse)
# =============================================================================

BEST_PRACTICES_RULES = [
    Rule(
        id="low-best-practices-score",
        category="best_practices",
        severity="medium",
        title="Low Best Practices Score",
        description="Your Lighthouse best practices score is below 80.",
        fix_suggestion="Review the best practices audit and address issues like console errors, deprecated APIs, and security vulnerabilities.",
        condition=lambda ctx: (
            _get_nested(ctx, "lighthouse.metrics.category_scores.best-practices") or 100
        )
        < 80,
    ),
]

# =============================================================================
# All Rules Combined
# =============================================================================

ALL_RULES = (
    PERFORMANCE_RULES
    + SEO_RULES
    + SECURITY_RULES
    + ACCESSIBILITY_RULES
    + ASSET_RULES
    + BEST_PRACTICES_RULES
)
