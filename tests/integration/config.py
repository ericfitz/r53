"""Integration-test configuration loader.

Reads .r53-itest.toml from the repo root. Requires Python 3.11+ for
stdlib tomllib; production r53.py still supports 3.10.
"""

from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


CONFIG_FILENAME = ".r53-itest.toml"
EXAMPLE_FILENAME = ".r53-itest.example.toml"


class ConfigError(RuntimeError):
    """Raised when integration-test config is missing or invalid."""


@dataclass(frozen=True)
class IntegrationConfig:
    domain: str
    profile: Optional[str]
    region: Optional[str]


def _repo_root() -> Path:
    # tests/integration/config.py -> parents[2] is repo root
    return Path(__file__).resolve().parents[2]


def load_config() -> IntegrationConfig:
    """Load integration config from the repo root.

    Raises ConfigError if the file is missing or malformed. The pytest
    fixture in tests/integration/conftest.py converts this into a skip.
    """
    if sys.version_info < (3, 11):
        raise ConfigError(
            "Integration tests require Python 3.11+ (for stdlib tomllib). "
            f"Current: {sys.version_info.major}.{sys.version_info.minor}"
        )

    path = _repo_root() / CONFIG_FILENAME
    if not path.exists():
        raise ConfigError(
            f"{CONFIG_FILENAME} not found at {path}. "
            f"Copy {EXAMPLE_FILENAME} to {CONFIG_FILENAME} and fill in values."
        )

    with path.open("rb") as f:
        data = tomllib.load(f)

    domain = data.get("domain")
    if not isinstance(domain, str) or not domain:
        raise ConfigError(f"{CONFIG_FILENAME}: 'domain' is required and must be a non-empty string")

    profile = data.get("profile")
    if profile is not None and not isinstance(profile, str):
        raise ConfigError(f"{CONFIG_FILENAME}: 'profile' must be a string if present")

    region = data.get("region")
    if region is not None and not isinstance(region, str):
        raise ConfigError(f"{CONFIG_FILENAME}: 'region' must be a string if present")

    return IntegrationConfig(domain=domain, profile=profile, region=region)
