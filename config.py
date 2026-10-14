"""
Application configuration. Secrets come from environment variables (or a
local .env file that is git-ignored) - nothing secret is hard-coded.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _secret_key(instance_dir: Path) -> str:
    """Use SECRET_KEY from the environment, else a random key stored locally
    in instance/.secret_key (created once, never committed)."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    instance_dir.mkdir(parents=True, exist_ok=True)
    key_file = instance_dir / ".secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    return key


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Config:
    APP_NAME = "URLGuard AI"
    APP_VERSION = "1.0.0"

    INSTANCE_DIR = Path(os.environ.get("URLGUARD_INSTANCE_DIR", BASE_DIR / "instance"))
    MODEL_DIR = Path(os.environ.get("URLGUARD_MODEL_DIR", BASE_DIR / "models"))
    # DATABASE_PATH, EVIDENCE_DIR (private, never served as static files) and
    # BATCH_DIR (temporary batch CSVs, auto-deleted) are derived from
    # INSTANCE_DIR inside create_app().

    SECRET_KEY = None  # filled in create_app()

    # Sessions / cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)  # set True behind HTTPS
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 30

    # CSRF (Flask-WTF)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # token valid for the session

    # Upload limits
    MAX_CONTENT_LENGTH = 12 * 1024 * 1024          # whole request
    BATCH_MAX_BYTES = 2 * 1024 * 1024              # CSV upload
    BATCH_MAX_ROWS = 5000
    BATCH_RESULT_TTL_SECONDS = 60 * 60
    EVIDENCE_MAX_BYTES = 5 * 1024 * 1024           # per file
    EVIDENCE_MAX_FILES = 5
    EVIDENCE_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}

    # Optional threat intelligence
    SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")



def secret_key_for(instance_dir: Path) -> str:
    return _secret_key(Path(instance_dir))


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
