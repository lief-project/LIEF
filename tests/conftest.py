"""
Module containing configuration functions for Pytest.
"""

from typing import cast

import lief
import pytest
from utils import has_private_samples, is_linux, is_x86_64


def pytest_configure(config):
    # See https://docs.pytest.org/en/stable/how-to/mark.html
    config.addinivalue_line("markers", "slow: mark test as slow.")
    config.addinivalue_line("markers", "private: the test needs private samples.")
    config.addinivalue_line("markers", "linux: the test needs to run on Linux.")
    config.addinivalue_line(
        "markers", "lief_extended: the test needs the extended version."
    )


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

    parser.addoption(
        "--skip-linux",
        action="store_true",
        help="Skip linux tests",
    )

    parser.addoption(
        "--skip-extended",
        action="store_true",
        help="Skip extended tests",
    )


def pytest_runtest_setup(item: pytest.Function):
    if item.get_closest_marker("slow") is not None:
        if item.config.getoption("--skip-slow"):
            pytest.skip("Skipping slow tests")

    if item.get_closest_marker("private") is not None:
        if item.config.getoption("--skip-private") or not has_private_samples():
            pytest.skip("Skipping private test")

    if linux_marker := item.get_closest_marker("linux"):
        args = cast(list[str], linux_marker.args)
        if item.config.getoption("--skip-linux") or not is_linux():
            pytest.skip("Skipping Linux test")
        if len(args) > 0:
            arch = args[0]
            if arch.lower().strip() in ("x86_64", "x64", "x86-64"):
                if not is_x86_64():
                    pytest.skip("Skipping Linux[x86_64] test")

    if item.get_closest_marker("lief_extended") is not None:
        if item.config.getoption("--skip-extended") or not lief.__extended__:
            pytest.skip("Skipping LIEF extended test")
