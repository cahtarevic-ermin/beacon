"""Security audit engine."""

import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from analyzers.base import AnalysisResult, BaseAnalyzer
from config import settings

logger = logging.getLogger(__name__)


class SecurityAnalyzer(BaseAnalyzer):
    """
    Analyzes website security posture.
    
    Checks:
    - HTTPS enforcement
    - SSL certificate validity and expiration
    - Security headers (CSP, HSTS, X-Frame-Options, etc.)
    - Exposed admin panels
    - Server information disclosure
    """

    # Security scoring weights (total = 100)
    WEIGHTS = {
        "https": 20,
        "ssl_certificate": 20,
        "security_headers": 40,
        "information_disclosure": 10,
        "admin_exposure": 10,
    }

    # Required security headers and their importance
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "HSTS",
            "severity": "high",
            "description": "Enforces HTTPS connections",
        },
        "content-security-policy": {
            "name": "CSP",
            "severity": "high",
            "description": "Prevents XSS and injection attacks",
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity": "medium",
            "description": "Prevents clickjacking attacks",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity": "medium",
            "description": "Prevents MIME type sniffing",
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection",
            "severity": "low",
            "description": "Legacy XSS filter (deprecated but still useful)",
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity": "medium",
            "description": "Controls referrer information",
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity": "medium",
            "description": "Controls browser features access",
        },
    }

    # Common admin paths to check
    ADMIN_PATHS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/phpMyAdmin",
        "/cpanel",
        "/webmail",
        "/login",
        "/admin/login",
        "/.env",
        "/.git/config",
        "/config.php",
        "/wp-config.php",
    ]

    @property
    def name(self) -> str:
        return "security"

    def analyze(self, url: str) -> AnalysisResult:
        """
        Run security audit on the given URL.
        
        Args:
            url: Website URL to audit
            
        Returns:
            AnalysisResult with security scores and issues
        """
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            
            # Run all checks
            checks = {
                "https": self._check_https(url),
                "ssl_certificate": self._check_ssl_certificate(hostname),
                "security_headers": self._check_security_headers(url),
                "information_disclosure": self._check_information_disclosure(url),
                "admin_exposure": self._check_admin_exposure(url),
            }

            # Calculate overall score
            score = self._calculate_score(checks)

            # Collect all issues
            issues = self._collect_issues(checks)

            # Build metrics
            metrics = {
                "score": score,
                "checks": checks,
                "issues": issues,
                "issues_count": len(issues),
                "hostname": hostname,
            }

            return AnalysisResult(
                score=score,
                metrics=metrics,
                raw_data={"checks": checks},
                success=True,
            )

        except Exception as e:
            logger.exception(f"Security audit failed for {url}: {e}")
            return AnalysisResult(
                score=None,
                metrics={},
                raw_data={},
                success=False,
                error=str(e),
            )

    def _check_https(self, url: str) -> dict:
        """Check if site uses HTTPS and redirects from HTTP."""
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"

        result = {
            "uses_https": is_https,
            "redirects_to_https": False,
            "score": 0,
            "issues": [],
        }

        if is_https:
            result["score"] = 100
        else:
            result["issues"].append("Site does not use HTTPS")

        # Check if HTTP redirects to HTTPS
        if is_https:
            http_url = url.replace("https://", "http://")
            try:
                with httpx.Client(
                    timeout=10,
                    follow_redirects=False,
                ) as client:
                    response = client.get(http_url)
                    location = response.headers.get("location", "")
                    if response.status_code in (301, 302, 307, 308) and "https://" in location:
                        result["redirects_to_https"] = True
            except Exception:
                pass  # HTTP might not be available

        return result

    def _check_ssl_certificate(self, hostname: str) -> dict:
        """Check SSL certificate validity and expiration."""
        result = {
            "valid": False,
            "issuer": None,
            "subject": None,
            "expires": None,
            "days_until_expiry": None,
            "score": 0,
            "issues": [],
        }

        try:
            # Remove port if present
            if ":" in hostname:
                hostname = hostname.split(":")[0]

            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Extract certificate info
                    result["valid"] = True
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))

                    # Check expiration
                    not_after = cert.get("notAfter")
                    if not_after:
                        # Parse SSL date format: 'Mar 10 23:59:59 2025 GMT'
                        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                        result["expires"] = expiry_date.isoformat()

                        days_left = (expiry_date - datetime.now(timezone.utc)).days
                        result["days_until_expiry"] = days_left

                        if days_left < 0:
                            result["issues"].append("SSL certificate has expired")
                            result["score"] = 0
                        elif days_left < 7:
                            result["issues"].append(f"SSL certificate expires in {days_left} days (critical)")
                            result["score"] = 30
                        elif days_left < 30:
                            result["issues"].append(f"SSL certificate expires in {days_left} days")
                            result["score"] = 70
                        else:
                            result["score"] = 100

        except ssl.SSLCertVerificationError as e:
            result["issues"].append(f"SSL certificate verification failed: {e.reason}")
        except ssl.SSLError as e:
            result["issues"].append(f"SSL error: {str(e)}")
        except socket.timeout:
            result["issues"].append("Connection timeout when checking SSL")
        except socket.gaierror:
            result["issues"].append("Could not resolve hostname")
        except Exception as e:
            result["issues"].append(f"SSL check failed: {str(e)}")

        return result

    def _check_security_headers(self, url: str) -> dict:
        """Check for presence and quality of security headers."""
        result = {
            "present": [],
            "missing": [],
            "headers": {},
            "score": 0,
            "issues": [],
        }

        try:
            with httpx.Client(
                timeout=settings.http_timeout,
                follow_redirects=True,
            ) as client:
                response = client.get(url)
                headers = {k.lower(): v for k, v in response.headers.items()}

            # Check each security header
            total_weight = 0
            earned_weight = 0

            header_weights = {
                "strict-transport-security": 25,
                "content-security-policy": 25,
                "x-frame-options": 15,
                "x-content-type-options": 15,
                "referrer-policy": 10,
                "permissions-policy": 10,
            }

            for header_key, header_info in self.SECURITY_HEADERS.items():
                weight = header_weights.get(header_key, 10)
                total_weight += weight

                if header_key in headers:
                    result["present"].append(header_info["name"])
                    result["headers"][header_key] = headers[header_key]
                    earned_weight += weight

                    # Check header quality
                    self._validate_header_value(header_key, headers[header_key], result)
                else:
                    result["missing"].append(header_info["name"])
                    result["issues"].append({
                        "header": header_info["name"],
                        "message": f"Missing {header_info['name']} header",
                        "severity": header_info["severity"],
                        "description": header_info["description"],
                    })

            # Calculate score based on weights
            if total_weight > 0:
                result["score"] = round((earned_weight / total_weight) * 100)

        except Exception as e:
            result["issues"].append({"message": f"Failed to check headers: {str(e)}", "severity": "high"})

        return result

    def _validate_header_value(self, header: str, value: str, result: dict) -> None:
        """Validate specific header values for security best practices."""
        if header == "strict-transport-security":
            if "max-age" not in value.lower():
                result["issues"].append({
                    "header": "HSTS",
                    "message": "HSTS header missing max-age directive",
                    "severity": "medium",
                })
            else:
                # Check max-age value
                match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        result["issues"].append({
                            "header": "HSTS",
                            "message": f"HSTS max-age is {max_age}s, recommend at least 31536000 (1 year)",
                            "severity": "low",
                        })

        elif header == "x-frame-options":
            value_upper = value.upper()
            if value_upper not in ("DENY", "SAMEORIGIN"):
                result["issues"].append({
                    "header": "X-Frame-Options",
                    "message": f"X-Frame-Options has unusual value: {value}",
                    "severity": "low",
                })

        elif header == "x-content-type-options":
            if value.lower() != "nosniff":
                result["issues"].append({
                    "header": "X-Content-Type-Options",
                    "message": "X-Content-Type-Options should be 'nosniff'",
                    "severity": "low",
                })

    def _check_information_disclosure(self, url: str) -> dict:
        """Check for server information disclosure."""
        result = {
            "server_header": None,
            "x_powered_by": None,
            "version_disclosed": False,
            "score": 100,
            "issues": [],
        }

        try:
            with httpx.Client(
                timeout=settings.http_timeout,
                follow_redirects=True,
            ) as client:
                response = client.get(url)
                headers = response.headers

            # Check Server header
            server = headers.get("server")
            if server:
                result["server_header"] = server
                # Check if version is disclosed
                if re.search(r"\d+\.\d+", server):
                    result["version_disclosed"] = True
                    result["issues"].append("Server header discloses version information")
                    result["score"] -= 30

            # Check X-Powered-By header
            powered_by = headers.get("x-powered-by")
            if powered_by:
                result["x_powered_by"] = powered_by
                result["issues"].append(f"X-Powered-By header discloses technology: {powered_by}")
                result["score"] -= 20

            # Check for ASP.NET version header
            aspnet_version = headers.get("x-aspnet-version")
            if aspnet_version:
                result["issues"].append(f"ASP.NET version disclosed: {aspnet_version}")
                result["score"] -= 20

            result["score"] = max(0, result["score"])

        except Exception as e:
            result["issues"].append(f"Failed to check information disclosure: {str(e)}")

        return result

    def _check_admin_exposure(self, url: str) -> dict:
        """Check for exposed admin panels and sensitive files."""
        result = {
            "exposed_paths": [],
            "checked_paths": len(self.ADMIN_PATHS),
            "score": 100,
            "issues": [],
        }

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            with httpx.Client(
                timeout=5,  # Short timeout for probing
                follow_redirects=False,
            ) as client:
                for path in self.ADMIN_PATHS:
                    try:
                        check_url = f"{base_url}{path}"
                        response = client.get(check_url)

                        # Consider it exposed if we get 200, 401, 403, or redirect
                        if response.status_code == 200:
                            result["exposed_paths"].append({
                                "path": path,
                                "status": response.status_code,
                                "severity": "high",
                            })
                            result["issues"].append(f"Exposed path found: {path} (accessible)")
                            result["score"] -= 20
                        elif response.status_code in (401, 403):
                            # Protected but visible
                            result["exposed_paths"].append({
                                "path": path,
                                "status": response.status_code,
                                "severity": "medium",
                            })
                            result["issues"].append(f"Admin path exists: {path} (protected)")
                            result["score"] -= 5
                        elif response.status_code in (301, 302, 307, 308):
                            location = response.headers.get("location", "")
                            if "login" in location.lower() or "admin" in location.lower():
                                result["exposed_paths"].append({
                                    "path": path,
                                    "status": response.status_code,
                                    "severity": "low",
                                })

                    except Exception:
                        pass  # Path doesn't exist or error, which is fine

            result["score"] = max(0, result["score"])

        except Exception as e:
            result["issues"].append(f"Failed to check admin exposure: {str(e)}")

        return result

    def _calculate_score(self, checks: dict) -> float:
        """Calculate weighted overall security score."""
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
            "https": "high",
            "ssl_certificate": "high",
            "security_headers": "medium",
            "information_disclosure": "low",
            "admin_exposure": "medium",
        }

        for check_name, check_result in checks.items():
            check_issues = check_result.get("issues", [])
            default_severity = severity_map.get(check_name, "low")

            for issue in check_issues:
                if isinstance(issue, dict):
                    issues.append({
                        "check": check_name,
                        "message": issue.get("message", str(issue)),
                        "severity": issue.get("severity", default_severity),
                    })
                else:
                    issues.append({
                        "check": check_name,
                        "message": str(issue),
                        "severity": default_severity,
                    })

        return issues


# Convenience function
def run_security_audit(url: str) -> AnalysisResult:
    """Run security audit on the given URL."""
    analyzer = SecurityAnalyzer()
    return analyzer.analyze(url)

