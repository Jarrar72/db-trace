"""Smoke tests for Phase 0 setup."""

from dbtrace import __version__
from dbtrace.config import settings


def test_version_and_settings() -> None:
    assert __version__ == "0.1.0"
    assert settings.random_seed == 42
