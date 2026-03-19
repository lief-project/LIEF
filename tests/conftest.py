"""
Module containing configuration functions for Pytest.
"""
import pytest

def pytest_configure(config):
    # See https://docs.pytest.org/en/stable/how-to/mark.html
    config.addinivalue_line(
        "markers", "slow: mark test as slow."
    )

def pytest_addoption(parser):
    parser.addoption(
        "--skip-slow",
        action="store_true",
        help="Skip slow tests",
    )

def pytest_runtest_setup(item: pytest.Function):
    if item.get_closest_marker('slow') is not None:
        if item.config.getoption('--skip-slow'):
            pytest.skip("Skipping slow tests")
