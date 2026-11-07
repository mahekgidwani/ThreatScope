"""Shared pytest setup.

The environment is prepared BEFORE any `app` module is imported, so tests never
use the real API key from `.env` (the container receives it as an env var).
"""
import os
import secrets

# Fresh random fake key for every test run. Tests that need it import TEST_API_KEY.
TEST_API_KEY = secrets.token_hex(16)

os.environ["APP_ENV"] = "test"
os.environ["INGEST_API_KEY"] = TEST_API_KEY

# Only fill these in when missing (inside Compose they point at the real `db`
# service; on a bare machine they are harmless dummies).
os.environ.setdefault("POSTGRES_USER", "test_user")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password-fake")
os.environ.setdefault("POSTGRES_DB", "test_db")
