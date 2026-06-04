"""
NetSpecter OpenRouter API Client

Client for interacting with OpenRouter's LLM API.
Supports multiple models for different analysis phases.
"""

import json
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from backend.config import settings

logger = structlog.get_logger(__name__)


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class LLMResponse:
    """Response from LLM API."""

    content: str
    """The generated text content."""

    model: str
    """Model that generated the response."""

    usage: dict[str, int]
    """Token usage statistics."""

    finish_reason: str
    """Why the generation stopped."""

    raw_response: dict | None = None
    """Raw API response for debugging."""


@dataclass
class LLMError:
    """Error from LLM API."""

    error_type: str
    message: str
    status_code: int | None = None


# =============================================================================
# OpenRouter Client
# =============================================================================


class OpenRouterClient:
    """
    Client for OpenRouter API.

    Provides access to multiple LLM models for different analysis phases.
    """

    API_BASE = "https://openrouter.ai/api/v1"

    # Model configurations
    MODELS = {
        "stats": settings.llm_model_stats,  # For statistical analysis
        "detection": settings.llm_model_detection,  # For detection analysis
        "synthesis": settings.llm_model_synthesis,  # For final synthesis
        "fast": settings.llm_model_fast,  # For quick decisions (e.g., VT prioritization)
    }

    def __init__(self, api_key: str | None = None):
        """
        Initialize the OpenRouter client.

        Args:
            api_key: OpenRouter API key. If not provided, uses settings.
        """
        self.api_key = api_key or settings.openrouter_api_key
        self._client: httpx.AsyncClient | None = None

    @property
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)

    # Models that require extended timeout (reasoning models)
    REASONING_MODELS = {
        "deepseek/deepseek-r1-0528:free",
        "tngtech/deepseek-r1t-chimera:free",
        "tngtech/deepseek-r1t2-chimera:free",
        "deepseek/deepseek-r1",
    }

    async def _get_client(self, timeout: float | None = None) -> httpx.AsyncClient:
        """Get or create HTTP client with appropriate timeout."""
        # Use configured timeout or default
        request_timeout = timeout or settings.llm_timeout_default
        
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.API_BASE,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "HTTP-Referer": "https://github.com/netspecter",
                    "X-Title": "NetSpecter",
                    "Content-Type": "application/json",
                },
                timeout=float(request_timeout),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        phase: str = "stats",
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse | LLMError:
        """
        Send a chat completion request.

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Specific model to use (overrides phase selection)
            phase: Analysis phase ('stats', 'detection', 'synthesis')
            temperature: Sampling temperature (0.0 - 1.0)
            max_tokens: Maximum tokens in response

        Returns:
            LLMResponse on success, LLMError on failure
        """
        if not self.is_configured:
            return LLMError(
                error_type="configuration",
                message="OpenRouter API key not configured",
            )

        # Select model
        if model is None:
            model = self.MODELS.get(phase, self.MODELS["stats"])

        # Determine timeout based on model type
        is_reasoning = any(r in model for r in ["deepseek-r1", "r1t-chimera", "r1t2-chimera"])
        timeout = settings.llm_timeout_reasoning if is_reasoning else settings.llm_timeout_default

        logger.info(
            "llm_request_starting",
            model=model,
            phase=phase,
            message_count=len(messages),
            timeout=timeout,
            is_reasoning_model=is_reasoning,
        )

        try:
            client = await self._get_client(timeout=float(timeout))

            response = await client.post(
                "/chat/completions",
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=float(timeout),
            )

            if response.status_code != 200:
                error_body = response.text
                logger.error(
                    "llm_request_failed",
                    status_code=response.status_code,
                    error=error_body,
                )
                return LLMError(
                    error_type="api_error",
                    message=f"API returned {response.status_code}: {error_body}",
                    status_code=response.status_code,
                )

            data = response.json()

            # Extract response content
            choices = data.get("choices", [])
            if not choices:
                return LLMError(
                    error_type="empty_response",
                    message="No choices in API response",
                )

            choice = choices[0]
            message = choice.get("message", {})
            content = message.get("content", "")
            finish_reason = choice.get("finish_reason", "unknown")
            
            # For reasoning models like deepseek-r1, the actual response might be
            # in the "reasoning" field if content is empty
            if not content and message.get("reasoning"):
                reasoning = message.get("reasoning", "")
                # Use reasoning content as the main content
                content = reasoning
                logger.debug(
                    "llm_using_reasoning_content",
                    model=model,
                    content_length=len(content),
                )

            # Extract usage stats
            usage = data.get("usage", {})

            logger.info(
                "llm_request_complete",
                model=model,
                tokens_prompt=usage.get("prompt_tokens", 0),
                tokens_completion=usage.get("completion_tokens", 0),
                finish_reason=finish_reason,
            )

            return LLMResponse(
                content=content,
                model=model,
                usage={
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0),
                },
                finish_reason=finish_reason,
                raw_response=data,
            )

        except httpx.TimeoutException:
            logger.error("llm_request_timeout", model=model)
            return LLMError(
                error_type="timeout",
                message="Request timed out after 120 seconds",
            )

        except httpx.RequestError as e:
            logger.error("llm_request_error", error=str(e))
            return LLMError(
                error_type="network_error",
                message=str(e),
            )

        except Exception as e:
            logger.error("llm_request_exception", error=str(e), exc_info=True)
            return LLMError(
                error_type="unknown",
                message=str(e),
            )

    async def analyze_statistics(
        self,
        prompt: str,
        system_prompt: str | None = None,
    ) -> LLMResponse | LLMError:
        """
        Analyze traffic statistics using the stats model.

        Args:
            prompt: The analysis prompt with statistics
            system_prompt: Optional system prompt override

        Returns:
            LLMResponse or LLMError
        """
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        return await self.chat(
            messages=messages,
            phase="stats",
            temperature=0.3,
            max_tokens=4096,
        )

    async def analyze_detections(
        self,
        prompt: str,
        system_prompt: str | None = None,
    ) -> LLMResponse | LLMError:
        """
        Analyze detection findings using the detection model.

        Args:
            prompt: The analysis prompt with detection results
            system_prompt: Optional system prompt override

        Returns:
            LLMResponse or LLMError
        """
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        return await self.chat(
            messages=messages,
            phase="detection",
            temperature=0.2,
            max_tokens=6144,
        )

    async def synthesize_findings(
        self,
        prompt: str,
        system_prompt: str | None = None,
    ) -> LLMResponse | LLMError:
        """
        Synthesize all findings using the synthesis model.

        Args:
            prompt: The synthesis prompt with all findings
            system_prompt: Optional system prompt override

        Returns:
            LLMResponse or LLMError
        """
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        return await self.chat(
            messages=messages,
            phase="synthesis",
            temperature=0.3,
            max_tokens=8192,
        )

    async def quick_analyze(
        self,
        prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 1024,
    ) -> LLMResponse | LLMError:
        """
        Quick analysis using the fast model.

        Used for rapid decisions like prioritizing indicators for VT lookup.
        Uses arcee-ai/trinity-large-preview for speed.

        Args:
            prompt: The analysis prompt
            system_prompt: Optional system prompt override
            max_tokens: Maximum tokens in response

        Returns:
            LLMResponse or LLMError
        """
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        return await self.chat(
            messages=messages,
            phase="fast",
            temperature=0.1,  # Low temperature for consistent decisions
            max_tokens=max_tokens,
        )


# =============================================================================
# Singleton Instance
# =============================================================================


_client_instance: OpenRouterClient | None = None


def get_openrouter_client() -> OpenRouterClient:
    """Get the singleton OpenRouter client instance."""
    global _client_instance
    if _client_instance is None:
        _client_instance = OpenRouterClient()
    return _client_instance
