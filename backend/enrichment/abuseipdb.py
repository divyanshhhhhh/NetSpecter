"""
NetSpecter AbuseIPDB Client

Queries AbuseIPDB API v2 for IP abuse reports.
Handles rate limiting (1000 requests/day for free tier).
"""

import asyncio
from typing import Any

import httpx
import structlog

from backend.config import settings
from backend.enrichment.models import AbuseIPDBResult

logger = structlog.get_logger(__name__)


class AbuseIPDBClient:
    """
    AbuseIPDB API v2 client.
    
    Features:
    - IP abuse check lookups
    - Automatic rate limiting
    - Report category parsing
    - Abuse confidence scoring
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    # Rate limiting: 1000/day = ~0.7/min
    # Allow higher bursts since we have 1000/day quota
    RATE_LIMIT = 30  # per minute for bursts
    RATE_PERIOD = 60
    
    def __init__(self, api_key: str | None = None):
        """
        Initialize the client.
        
        Args:
            api_key: AbuseIPDB API key (defaults to settings)
        """
        self.api_key = api_key or settings.abuseipdb_api_key
        
        # Rate limiting state
        self._request_times: list[float] = []
        self._rate_lock = asyncio.Lock()
    
    @property
    def is_configured(self) -> bool:
        """Check if API key is available."""
        return bool(self.api_key)
    
    async def _wait_for_rate_limit(self) -> None:
        """Wait if rate limit would be exceeded."""
        async with self._rate_lock:
            now = asyncio.get_event_loop().time()
            
            # Remove old request times
            self._request_times = [
                t for t in self._request_times
                if now - t < self.RATE_PERIOD
            ]
            
            # If at limit, wait
            if len(self._request_times) >= self.RATE_LIMIT:
                oldest = min(self._request_times)
                wait_time = self.RATE_PERIOD - (now - oldest) + 0.5
                if wait_time > 0:
                    logger.debug("abuseipdb_rate_limit_wait", seconds=wait_time)
                    await asyncio.sleep(wait_time)
            
            # Record this request
            self._request_times.append(now)
    
    async def _make_request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any] | None:
        """
        Make an authenticated request to AbuseIPDB.
        
        Args:
            endpoint: API endpoint path
            params: Query parameters
            timeout: Request timeout in seconds
        
        Returns:
            JSON response data or None on error
        """
        if not self.is_configured:
            return None
        
        await self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}{endpoint}"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers=headers,
                    params=params or {},
                    timeout=timeout,
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 401:
                    logger.error("abuseipdb_unauthorized")
                    return {"error": "unauthorized"}
                elif response.status_code == 422:
                    logger.debug("abuseipdb_invalid_ip", params=params)
                    return {"error": "invalid_ip"}
                elif response.status_code == 429:
                    logger.warning("abuseipdb_rate_limited")
                    return {"error": "rate_limited"}
                else:
                    logger.warning(
                        "abuseipdb_error",
                        status=response.status_code,
                        endpoint=endpoint,
                    )
                    return {"error": f"http_{response.status_code}"}
                    
        except httpx.TimeoutException:
            logger.warning("abuseipdb_timeout", endpoint=endpoint)
            return {"error": "timeout"}
        except httpx.RequestError as e:
            logger.error("abuseipdb_request_error", error=str(e))
            return {"error": str(e)}
    
    async def check_ip(
        self,
        ip: str,
        max_age_days: int = 90,
        verbose: bool = True,
    ) -> AbuseIPDBResult:
        """
        Check an IP for abuse reports.
        
        Args:
            ip: IP address to check
            max_age_days: Maximum age of reports to include (1-365)
            verbose: Include detailed report info
        
        Returns:
            AbuseIPDBResult with abuse data
        """
        result = AbuseIPDBResult(ip_address=ip)
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": min(365, max(1, max_age_days)),
            "verbose": str(verbose).lower(),
        }
        
        data = await self._make_request("/check", params=params)
        
        if data is None:
            result.error = "API key not configured"
            return result
        
        if "error" in data:
            result.error = data["error"]
            return result
        
        # Parse response
        try:
            info = data.get("data", {})
            
            # Core metrics
            result.abuse_confidence_score = info.get("abuseConfidenceScore", 0)
            result.total_reports = info.get("totalReports", 0)
            result.distinct_users = info.get("numDistinctUsers", 0)
            
            # Flags
            result.is_whitelisted = info.get("isWhitelisted", False)
            result.is_tor_node = info.get("isTor", False)
            
            # Network info
            result.country_code = info.get("countryCode")
            result.isp = info.get("isp")
            result.domain = info.get("domain")
            result.usage_type = info.get("usageType")
            
            # Last reported
            result.last_reported_at = info.get("lastReportedAt")
            
            # Extract categories from reports if verbose
            reports = info.get("reports", [])
            all_categories = set()
            for report in reports:
                cats = report.get("categories", [])
                all_categories.update(cats)
            result.categories = sorted(all_categories)
            
            logger.debug(
                "abuseipdb_check",
                ip=ip,
                score=result.abuse_confidence_score,
                reports=result.total_reports,
            )
            
        except Exception as e:
            logger.error("abuseipdb_parse_error", ip=ip, error=str(e))
            result.error = f"Parse error: {e}"
        
        return result
    
    async def lookup(self, indicator: str, indicator_type: str) -> AbuseIPDBResult | None:
        """
        Look up an indicator.
        
        Note: AbuseIPDB only supports IP lookups.
        
        Args:
            indicator: IP to check
            indicator_type: "ip" (domain not supported)
        
        Returns:
            AbuseIPDBResult or None if not applicable
        """
        if indicator_type == "ip":
            return await self.check_ip(indicator)
        else:
            # AbuseIPDB only supports IPs
            return None


# Singleton instance
_client_instance: AbuseIPDBClient | None = None


def get_abuseipdb_client() -> AbuseIPDBClient:
    """Get or create the global AbuseIPDB client."""
    global _client_instance
    if _client_instance is None:
        _client_instance = AbuseIPDBClient()
    return _client_instance
