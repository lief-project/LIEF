"""
Module containing configuration functions for Pytest.
"""

import pytest
from utils import has_private_samples


def pytest_configure(config):
    # See https://docs.pytest.org/en/stable/how-to/mark.html
    config.addinivalue_line("markers", "slow: mark test as slow.")
    config.addinivalue_line("markers", "private: the test needs private samples.")


def pytest_addoption(parser):
    parser.addoption(
        "--skip-slow",
        action="store_true",
        help="Skip slow tests",
    )

    parser.addoption(
        "--skip-private",
        action="store_true",
        help="Skip private tests",
    )


def pytest_runtest_setup(item: pytest.Function):
    if item.get_closest_marker("slow") is not None:
        if item.config.getoption("--skip-slow"):
            pytest.skip("Skipping slow tests")

    if item.get_closest_marker("private") is not None:
        if item.config.getoption("--skip-private") or not has_private_samples():
            pytest.skip("Skipping private test")
