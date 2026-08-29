import os

from dotenv import load_dotenv

load_dotenv()

# Single source of truth for the LLM model used across all LLM call sites.
# Can be overridden by LLM_MODEL env var; falls back to claude-sonnet-4-20250514
LLM_MODEL = os.environ.get("LLM_MODEL", "claude-sonnet-4-20250514")
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic")  # anthropic or openrouter

def get_config():
    # API keys are checked lazily in the LLM client; we only need to ensure
    # that at least one of the possible keys is set when not in test mode.
    # For simplicity, we still return the anthropic key if present, but
    # the LLM client will handle missing keys with a dummy in pytest.
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    openrouter_key = os.environ.get("OPENROUTER_API_KEY")

    # In non-test environments, require at least one key to be set.
    if "PYTEST_CURRENT_TEST" not in os.environ:
        if not api_key and not openrouter_key:
            raise RuntimeError(
                "Missing required API key. Set either ANTHROPIC_API_KEY or OPENROUTER_API_KEY. "
                "See .env.example for details."
            )

    return {
        "ANTHROPIC_API_KEY": api_key,
        "OPENROUTER_API_KEY": openrouter_key,
        "LLM_MODEL": LLM_MODEL,
        "LLM_PROVIDER": LLM_PROVIDER,
        "FUZZ_TIMEOUT_S": int(os.environ.get("FUZZ_TIMEOUT_S", "300")),
        "MAX_RETRIES": int(os.environ.get("MAX_RETRIES", "3")),
        "TEMPLATE_CONFIDENCE_THRESHOLD": float(os.environ.get("TEMPLATE_CONFIDENCE_THRESHOLD", "0.8")),
    }
