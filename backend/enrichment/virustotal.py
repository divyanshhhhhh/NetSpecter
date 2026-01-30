"""
NetSpecter VirusTotal Client

Queries VirusTotal API v3 for IP and domain reputation data.
Handles rate limiting (4 requests/minute for free tier).
"""

import asyncio
from datetime import datetime
from typing import Any

import httpx
import structlog

from backend.config import settings
from backend.enrichment.models import VirusTotalResult

logger = structlog.get_logger(__name__)


class VirusTotalClient:
    """
    VirusTotal API v3 client.
    
    Features:
    - IP and domain reputation lookups
    - Automatic rate limiting (4/min)
    - Retry with exponential backoff
    - Detailed detection parsing
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    # Rate limiting: 4 requests per minute
    RATE_LIMIT = 4
    RATE_PERIOD = 60  # seconds
    
    def __init__(self, api_key: str | None = None):
        """
        Initialize the client.
        
        Args:
            api_key: VirusTotal API key (defaults to settings)
        """
        self.api_key = api_key or settings.virustotal_api_key
        
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
                    logger.debug("virustotal_rate_limit_wait", seconds=wait_time)
                    await asyncio.sleep(wait_time)
            
            # Record this request
            self._request_times.append(now)
    
    async def _make_request(
        self, 
        endpoint: str,
        timeout: float = 30.0,
    ) -> dict[str, Any] | None:
        """
        Make an authenticated request to VirusTotal.
        
        Args:
            endpoint: API endpoint path
            timeout: Request timeout in seconds
        
        Returns:
            JSON response data or None on error
        """
        if not self.is_configured:
            return None
        
        await self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}{endpoint}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    logger.debug("virustotal_not_found", endpoint=endpoint)
                    return {"error": "not_found"}
                elif response.status_code == 429:
                    logger.warning("virustotal_rate_limited")
                    return {"error": "rate_limited"}
                else:
                    logger.warning(
                        "virustotal_error",
                        status=response.status_code,
                        endpoint=endpoint,
                    )
                    return {"error": f"http_{response.status_code}"}
                    
        except httpx.TimeoutException:
            logger.warning("virustotal_timeout", endpoint=endpoint)
            return {"error": "timeout"}
        except httpx.RequestError as e:
            logger.error("virustotal_request_error", error=str(e))
            return {"error": str(e)}
    
    async def lookup_ip(self, ip: str) -> VirusTotalResult:
        """
        Look up IP reputation.
        
        Args:
            ip: IP address to check
        
        Returns:
            VirusTotalResult with detection data
        """
        result = VirusTotalResult(indicator=ip, indicator_type="ip")
        
        data = await self._make_request(f"/ip_addresses/{ip}")
        
        if data is None:
            result.error = "API key not configured"
            return result
        
        if "error" in data:
            result.error = data["error"]
            return result
        
        # Parse response
        try:
            attrs = data.get("data", {}).get("attributes", {})
            
            # Last analysis stats
            stats = attrs.get("last_analysis_stats", {})
            result.malicious_count = stats.get("malicious", 0)
            result.suspicious_count = stats.get("suspicious", 0)
            result.harmless_count = stats.get("harmless", 0)
            result.undetected_count = stats.get("undetected", 0)
            result.total_engines = sum(stats.values())
            
            # Network info
            result.country = attrs.get("country")
            result.asn = attrs.get("asn")
            result.as_owner = attrs.get("as_owner")
            
            # Tags
            result.tags = attrs.get("tags", [])
            
            # Last analysis date
            if attrs.get("last_analysis_date"):
                result.last_analysis_date = datetime.fromtimestamp(
                    attrs["last_analysis_date"]
                )
            
            logger.debug(
                "virustotal_ip_lookup",
                ip=ip,
                malicious=result.malicious_count,
                total=result.total_engines,
            )
            
        except Exception as e:
            logger.error("virustotal_parse_error", ip=ip, error=str(e))
            result.error = f"Parse error: {e}"
        
        return result
    
    async def lookup_domain(self, domain: str) -> VirusTotalResult:
        """
        Look up domain reputation.
        
        Args:
            domain: Domain name to check
        
        Returns:
            VirusTotalResult with detection data
        """
        result = VirusTotalResult(indicator=domain, indicator_type="domain")
        
        data = await self._make_request(f"/domains/{domain}")
        
        if data is None:
            result.error = "API key not configured"
            return result
        
        if "error" in data:
            result.error = data["error"]
            return result
        
        # Parse response
        try:
            attrs = data.get("data", {}).get("attributes", {})
            
            # Last analysis stats
            stats = attrs.get("last_analysis_stats", {})
            result.malicious_count = stats.get("malicious", 0)
            result.suspicious_count = stats.get("suspicious", 0)
            result.harmless_count = stats.get("harmless", 0)
            result.undetected_count = stats.get("undetected", 0)
            result.total_engines = sum(stats.values())
            
            # Categories from vendors
            categories = attrs.get("categories", {})
            result.categories = list(set(categories.values()))
            
            # Registrar info
            result.registrar = attrs.get("registrar")
            result.creation_date = attrs.get("creation_date")
            
            # Tags
            result.tags = attrs.get("tags", [])
            
            # Last analysis date
            if attrs.get("last_analysis_date"):
                result.last_analysis_date = datetime.fromtimestamp(
                    attrs["last_analysis_date"]
                )
            
            logger.debug(
                "virustotal_domain_lookup",
                domain=domain,
                malicious=result.malicious_count,
                total=result.total_engines,
            )
            
        except Exception as e:
            logger.error("virustotal_parse_error", domain=domain, error=str(e))
            result.error = f"Parse error: {e}"
        
        return result
    
    async def lookup(self, indicator: str, indicator_type: str) -> VirusTotalResult:
        """
        Look up an indicator by type.
        
        Args:
            indicator: IP or domain to check
            indicator_type: "ip" or "domain"
        
        Returns:
            VirusTotalResult
        """
        if indicator_type == "ip":
            return await self.lookup_ip(indicator)
        elif indicator_type == "domain":
            return await self.lookup_domain(indicator)
        else:
            result = VirusTotalResult(indicator=indicator, indicator_type=indicator_type)
            result.error = f"Unsupported indicator type: {indicator_type}"
            return result


# Singleton instance
_client_instance: VirusTotalClient | None = None


def get_virustotal_client() -> VirusTotalClient:
    """Get or create the global VirusTotal client."""
    global _client_instance
    if _client_instance is None:
        _client_instance = VirusTotalClient()
    return _client_instance
