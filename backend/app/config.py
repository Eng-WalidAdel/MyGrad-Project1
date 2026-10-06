"""Application configuration loaded from environment variables.

Teammates: never hardcode API keys. Copy `.env.example` to `.env` and fill values.
"""

import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Runtime settings sourced from the process environment."""

    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")


settings = Settings()
