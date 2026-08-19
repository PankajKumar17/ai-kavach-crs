import os

from dotenv import load_dotenv

load_dotenv()

def get_config():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("Missing required environment variable: ANTHROPIC_API_KEY. Please set it in .env or your environment.")
        
    return {
        "ANTHROPIC_API_KEY": api_key,
        "FUZZ_TIMEOUT_S": int(os.environ.get("FUZZ_TIMEOUT_S", "300")),
        "MAX_RETRIES": int(os.environ.get("MAX_RETRIES", "3")),
        "TEMPLATE_CONFIDENCE_THRESHOLD": float(os.environ.get("TEMPLATE_CONFIDENCE_THRESHOLD", "0.8")),
    }
