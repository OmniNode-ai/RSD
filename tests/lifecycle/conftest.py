"""Local test options for optional PostgreSQL integration coverage."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the explicit gate for externally supplied PostgreSQL tests."""

    parser.addoption(
        "--postgres-integration",
        action="store_true",
        default=False,
        help="run integration tests with an externally injected isolated PostgreSQL factory",
    )
    parser.addoption(
        "--journal-diagnostic-runs",
        action="store",
        type=int,
        default=1,
        help="run a bounded SQLite authorization-journal diagnostic stress case",
    )
