"""Isolated OpenAI adapter for advisory AI responses; no PayPal functionality."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

DEFAULT_MODEL = "gpt-4.1-mini"
PROVIDER_TIMEOUT_SECONDS = 20.0
MAX_OUTPUT_CHARS = 8_000

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[^\s,;]+"),
)


class AIConfigurationError(RuntimeError):
    """Required runtime configuration is absent."""


class AIProviderTimeout(RuntimeError):
    """The provider exceeded the configured request timeout."""


class AIProviderError(RuntimeError):
    """A provider request failed without exposing provider internals."""


@dataclass(frozen=True)
class AIResult:
    text: str
    model: str


def filter_sensitive_output(text: str) -> str:
    """Redact common credential forms and trim unsafe surrounding whitespace."""
    filtered = text.strip()
    for pattern in _SECRET_PATTERNS:
        filtered = pattern.sub("[REDACTED]", filtered)
    for env_name in ("OPENAI_API_KEY", "TRUSTGUARD_API_BEARER_TOKEN"):
        secret = os.getenv(env_name, "")
        if len(secret) >= 8:
            filtered = filtered.replace(secret, "[REDACTED]")
    return filtered[:MAX_OUTPUT_CHARS]


async def generate_ai_response(prompt: str) -> AIResult:
    """Call OpenAI only on the server; never log prompts or provider error bodies."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise AIConfigurationError("OpenAI credentials are not configured.")

    model = os.getenv("OPENAI_MODEL", DEFAULT_MODEL).strip()
    if not model or len(model) > 100:
        raise AIConfigurationError("OpenAI model configuration is invalid.")

    try:
        from openai import APIConnectionError, APITimeoutError, AsyncOpenAI, OpenAIError
    except ImportError:
        raise AIConfigurationError("OpenAI SDK is unavailable.") from None

    try:
        async with AsyncOpenAI(
            api_key=api_key,
            timeout=PROVIDER_TIMEOUT_SECONDS,
            max_retries=0,
        ) as client:
            response = await client.responses.create(
                model=model,
                input=prompt,
                timeout=PROVIDER_TIMEOUT_SECONDS,
            )
        output = response.output_text
        if not isinstance(output, str) or not output.strip():
            raise AIProviderError("Provider returned no usable text.")
        filtered = filter_sensitive_output(output)
        if not filtered:
            raise AIProviderError("Provider returned no usable text.")
        return AIResult(text=filtered, model=model)
    except APITimeoutError:
        raise AIProviderTimeout("OpenAI request timed out.") from None
    except (APIConnectionError, OpenAIError):
        raise AIProviderError("OpenAI request failed.") from None
