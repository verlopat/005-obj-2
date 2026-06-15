"""Pytest configuration for the test suite."""
import pytest

@pytest.fixture(autouse=True)
def reset_env(monkeypatch):
    """Ensure each test starts with clean environment overrides."""
    yield
