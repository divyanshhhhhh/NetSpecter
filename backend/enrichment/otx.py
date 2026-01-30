"""
NetSpecter AlienVault OTX Client

Queries AlienVault Open Threat Exchange (OTX) API for threat intelligence.
Handles rate limiting (10000 requests/day for free tier).
"""

import asyncio
from typing import Any

import httpx
import structlog

from backend.config import settings
from backend.enrichment.models import OTXResult

logger = structlog.get_logger(__name__)


class OTXClient:
    """
    AlienVault OTX API client.
    
    Features:
    - IP, domain, and hostname lookups
    - Pulse (threat report) parsing
    - Malware family extraction
    - Geographic info retrieval
    """
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    # Rate limiting: 10000/day = ~7/min, allow reasonable bursts
    RATE_LIMIT = 15  # per minute
    RATE_PERIOD = 60
    
    def __init__(self, api_key: str | None = None):
        """
        Initialize the client.
        
        Args:
            api_key: OTX API key (defaults to settings)
        """
        self.api_key = api_key or settings.otx_api_key
        
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
                    logger.debug("otx_rate_limit_wait", seconds=wait_time)
                    await asyncio.sleep(wait_time)
            
            # Record this request
            self._request_times.append(now)
    
    async def _make_request(
        self,
        endpoint: str,
        timeout: float = 30.0,
    ) -> dict[str, Any] | None:
        """
        Make an authenticated request to OTX.
        
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
            "X-OTX-API-KEY": self.api_key,
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
                elif response.status_code == 400:
                    logger.debug("otx_bad_request", endpoint=endpoint)
                    return {"error": "bad_request"}
                elif response.status_code == 403:
                    logger.error("otx_forbidden")
                    return {"error": "forbidden"}
                elif response.status_code == 404:
                    logger.debug("otx_not_found", endpoint=endpoint)
                    return {"error": "not_found"}
                elif response.status_code == 429:
                    logger.warning("otx_rate_limited")
                    return {"error": "rate_limited"}
                else:
                    logger.warning(
                        "otx_error",
                        status=response.status_code,
                        endpoint=endpoint,
                    )
                    return {"error": f"http_{response.status_code}"}
                    
        except httpx.TimeoutException:
            logger.warning("otx_timeout", endpoint=endpoint)
            return {"error": "timeout"}
        except httpx.RequestError as e:
            logger.error("otx_request_error", error=str(e))
            return {"error": str(e)}
    
    async def lookup_ip(self, ip: str) -> OTXResult:
        """
        Look up IP threat intelligence.
        
        Args:
            ip: IP address to check
        
        Returns:
            OTXResult with pulse and threat data
        """
        result = OTXResult(indicator=ip, indicator_type="IPv4")
        
        # Get general info
        general_data = await self._make_request(f"/indicators/IPv4/{ip}/general")
        
        if general_data is None:
            result.error = "API key not configured"
            return result
        
        if "error" in general_data:
            result.error = general_data["error"]
            return result
        
        try:
            # Pulse count
            result.pulse_count = general_data.get("pulse_info", {}).get("count", 0)
            
            # Pulse summaries
            pulses = general_data.get("pulse_info", {}).get("pulses", [])
            result.pulses = [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "created": p.get("created"),
                    "tags": p.get("tags", []),
                }
                for p in pulses[:10]  # Limit to 10
            ]
            
            # Collect all tags
            all_tags = set()
            for pulse in pulses:
                all_tags.update(pulse.get("tags", []))
            result.tags = sorted(all_tags)
            
            # Extract malware families from tags
            malware_keywords = ["malware", "trojan", "rat", "ransomware", "botnet", "c2", "apt"]
            result.malware_families = [
                tag for tag in all_tags
                if any(kw in tag.lower() for kw in malware_keywords)
            ]
            
            # Geo info
            result.country_code = general_data.get("country_code")
            result.country_name = general_data.get("country_name")
            result.city = general_data.get("city")
            result.asn = general_data.get("asn")
            
            # Validation
            result.validation = general_data.get("validation", [])
            
            logger.debug(
                "otx_ip_lookup",
                ip=ip,
                pulses=result.pulse_count,
                tags=len(result.tags),
            )
            
        except Exception as e:
            logger.error("otx_parse_error", ip=ip, error=str(e))
            result.error = f"Parse error: {e}"
        
        return result
    
    async def lookup_domain(self, domain: str) -> OTXResult:
        """
        Look up domain threat intelligence.
        
        Args:
            domain: Domain name to check
        
        Returns:
            OTXResult with pulse and threat data
        """
        result = OTXResult(indicator=domain, indicator_type="domain")
        
        # Get general info
        general_data = await self._make_request(f"/indicators/domain/{domain}/general")
        
        if general_data is None:
            result.error = "API key not configured"
            return result
        
        if "error" in general_data:
            result.error = general_data["error"]
            return result
        
        try:
            # Pulse count
            result.pulse_count = general_data.get("pulse_info", {}).get("count", 0)
            
            # Pulse summaries
            pulses = general_data.get("pulse_info", {}).get("pulses", [])
            result.pulses = [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "created": p.get("created"),
                    "tags": p.get("tags", []),
                }
                for p in pulses[:10]
            ]
            
            # Collect all tags
            all_tags = set()
            for pulse in pulses:
                all_tags.update(pulse.get("tags", []))
            result.tags = sorted(all_tags)
            
            # Extract malware families
            malware_keywords = ["malware", "trojan", "rat", "ransomware", "botnet", "c2", "apt"]
            result.malware_families = [
                tag for tag in all_tags
                if any(kw in tag.lower() for kw in malware_keywords)
            ]
            
            # Validation
            result.validation = general_data.get("validation", [])
            
            logger.debug(
                "otx_domain_lookup",
                domain=domain,
                pulses=result.pulse_count,
                tags=len(result.tags),
            )
            
        except Exception as e:
            logger.error("otx_parse_error", domain=domain, error=str(e))
            result.error = f"Parse error: {e}"
        
        return result
    
    async def lookup(self, indicator: str, indicator_type: str) -> OTXResult:
        """
        Look up an indicator by type.
        
        Args:
            indicator: IP or domain to check
            indicator_type: "ip" or "domain"
        
        Returns:
            OTXResult
        """
        if indicator_type == "ip":
            return await self.lookup_ip(indicator)
        elif indicator_type == "domain":
            return await self.lookup_domain(indicator)
        else:
            result = OTXResult(indicator=indicator, indicator_type=indicator_type)
            result.error = f"Unsupported indicator type: {indicator_type}"
            return result


# Singleton instance
_client_instance: OTXClient | None = None


def get_otx_client() -> OTXClient:
    """Get or create the global OTX client."""
    global _client_instance
    if _client_instance is None:
        _client_instance = OTXClient()
    return _client_instance
