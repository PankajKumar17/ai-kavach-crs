"""Unified LLM client supporting multiple providers.

Supports:
- Anthropic (direct)
- OpenRouter (anthropic/claude, deepseek, gemini, glm-5, nemotron, etc.)
- Any OpenAI-compatible API
"""

import os
import time
from typing import Any


class LLMError(Exception):
    """Base exception for LLM client errors."""


# Default fallback models for OpenRouter (free/cheap models that work well)
DEFAULT_FALLBACK_MODELS = [
    "deepseek/deepseek-chat",
    "nvidia/nemotron-3-ultra",
    "google/gemini-2.0-flash-exp:free",
    "z-ai/glm-4.5v:free",
]


class LLMClient:
    """Unified client that adapts to different LLM providers."""

    def __init__(self):
        """Initialize client based on LLM_PROVIDER env var."""
        self.provider = os.environ.get("LLM_PROVIDER", "anthropic").lower()
        # Wall-clock ceiling for ONE create_message call (primary + fallbacks
        # combined). Set fresh by create_message; inf until then.
        self._turn_deadline = float("inf")

        # Parse fallback models from env var (comma-separated) or use defaults
        fallback_env = os.environ.get("LLM_FALLBACK_MODELS", "").strip()
        if fallback_env:
            self.fallback_models = [m.strip() for m in fallback_env.split(",") if m.strip()]
        else:
            self.fallback_models = DEFAULT_FALLBACK_MODELS

        if self.provider == "anthropic":
            self._init_anthropic()
        elif self.provider == "openrouter":
            self._init_openrouter()
        else:
            raise LLMError(f"Unsupported LLM_PROVIDER: {self.provider}")

    def _init_anthropic(self):
        """Initialize direct Anthropic client."""
        from anthropic import Anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            if "PYTEST_CURRENT_TEST" not in os.environ:
                raise RuntimeError("ANTHROPIC_API_KEY is not set.")
            api_key = "dummy_test_key"

        self.client = Anthropic(api_key=api_key)
        self.model = os.environ.get("LLM_MODEL", "claude-sonnet-4-20250514")
        self._call_fn = self._call_anthropic

    def _init_openrouter(self):
        """Initialize OpenRouter client (OpenAI-compatible API)."""
        try:
            from openai import OpenAI
        except ImportError as e:
            raise LLMError(
                "openai package not installed. Run: pip install openai"
            ) from e

        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            if "PYTEST_CURRENT_TEST" not in os.environ:
                raise RuntimeError("OPENROUTER_API_KEY is not set.")
            api_key = "dummy_test_key"

        self.client = OpenAI(
            # Overridable for testing / self-hosted OpenAI-compatible endpoints
            base_url=os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            api_key=api_key,
        )
        # Default to Claude Sonnet via OpenRouter, but allow override
        self.model = os.environ.get("LLM_MODEL", "anthropic/claude-sonnet-4.5")
        self._call_fn = self._call_openrouter

    def create_message(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.0,
        system: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a message using the configured provider with automatic fallback.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature (0 = deterministic).
            system: Optional system prompt.

        Returns:
            Provider response normalized to Anthropic's format:
            {
                "content": [{"type": "text", "text": "..."}],
                "stop_reason": "end_turn" | "max_tokens",
                ...
            }

        Raises:
            LLMError: If all models (primary + fallbacks) fail.
        """
        # One create_message call = one "turn". The whole turn (primary +
        # every fallback) must fit inside LLM_CALL_BUDGET_S, so the worst
        # case is bounded no matter how many fallback models are configured.
        budget_s = float(os.environ.get("LLM_CALL_BUDGET_S", "180"))
        self._turn_deadline = time.monotonic() + budget_s

        # Try primary model first
        try:
            response = self._call_fn(messages, max_tokens, temperature, system)
            # Check for empty response - treat as failure to trigger fallback
            if self._is_empty_response(response):
                raise LLMError("Empty response from primary model")
            return response
        except Exception as e:
            # If we have fallback models, try them
            if self.fallback_models and self.provider == "openrouter":
                return self._try_fallbacks(messages, max_tokens, temperature, system, e)
            raise

    def _is_empty_response(self, response: dict[str, Any]) -> bool:
        """Check if response has empty content."""
        content = response.get("content", [])
        if not content:
            return True
        for block in content:
            if block.get("type") == "text" and block.get("text", "").strip():
                return False
        return True

    def _try_fallbacks(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        system: str | None,
        last_error: Exception,
    ) -> dict[str, Any]:
        """Try fallback models in order."""
        import logging
        logger = logging.getLogger(__name__)

        original_model = self.model
        for fallback_model in self.fallback_models:
            try:
                logger.info("Primary model %s failed (%s), trying fallback: %s",
                           original_model, last_error, fallback_model)
                self.model = fallback_model
                response = self._call_fn(messages, max_tokens, temperature, system)
                if self._is_empty_response(response):
                    raise LLMError(f"Empty response from fallback model {fallback_model}")
                logger.info("Fallback model %s succeeded", fallback_model)
                return response
            except Exception as e:
                last_error = e
                logger.warning("Fallback model %s failed: %s", fallback_model, e)
                continue

        # All fallbacks exhausted
        self.model = original_model
        raise LLMError(
            f"All models failed (primary + {len(self.fallback_models)} "
            f"fallbacks). Last error: {last_error}"
        ) from last_error

    def _call_anthropic(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        system: str | None,
    ) -> dict[str, Any]:
        """Call Anthropic API directly."""
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        response = self.client.messages.create(**kwargs)

        # Return as dict (response is already an Anthropic Message object)
        return {
            "content": [{"type": "text", "text": block.text} for block in response.content],
            "stop_reason": response.stop_reason,
            "model": response.model,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
        }

    def _call_openrouter(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        system: str | None,
    ) -> dict[str, Any]:
        """Call OpenRouter (OpenAI-compatible API)."""
        # OpenAI format: system message is part of messages array
        openai_messages = []
        if system:
            openai_messages.append({"role": "system", "content": system})
        openai_messages.extend(messages)

        # Hard wall-clock cap per call. A stalled OpenRouter request once hung
        # a pipeline run for ~55 minutes; the RCA caller retries on failure,
        # and the template patch tier covers us when the LLM path is down.
        timeout_s = float(os.environ.get("LLM_CALL_TIMEOUT_S", "120"))

        # Turn-budget enforcement: if the primary + earlier fallbacks already
        # burned the turn's budget, don't start another 120s-capable request.
        if time.monotonic() > self._turn_deadline:
            raise LLMError(
                f"LLM turn budget exhausted ({os.environ.get('LLM_CALL_BUDGET_S', '180')}s) "
                f"before calling {self.model}"
            )

        response = self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout_s,
        )

        # Normalize to Anthropic format
        message = response.choices[0].message
        content_text = message.content or ""

        return {
            "content": [{"type": "text", "text": content_text}],
            "stop_reason": response.choices[0].finish_reason,  # "stop" | "length"
            "model": response.model,
            "usage": {
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
            }
        }


# Exception classes for compatibility
class APIConnectionError(LLMError):
    """Network/connection error."""


class APIStatusError(LLMError):
    """API returned an error status."""


class RateLimitError(LLMError):
    """Rate limit exceeded."""


def create_client() -> LLMClient:
    """Factory function to create an LLM client."""
    return LLMClient()
