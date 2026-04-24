"""Fixtures for integration tests.

All tests in this directory are implicitly tagged with the `integration`
pytest marker (via pytest_collection_modifyitems below), so they only
run when -m integration is passed. They require .r53-itest.toml.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

from .cleanup import sweep
from .config import ConfigError, IntegrationConfig, load_config


logger = logging.getLogger(__name__)


def pytest_collection_modifyitems(config, items):
    """Auto-apply the `integration` marker to every test in this package."""
    marker = pytest.mark.integration
    for item in items:
        # Only mark items under tests/integration/
        if "tests/integration/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(marker)


@pytest.fixture(scope="session")
def integration_config() -> IntegrationConfig:
    """Load the integration config or skip the session if missing."""
    try:
        return load_config()
    except ConfigError as e:
        pytest.skip(str(e))


@pytest.fixture(scope="session", autouse=True)
def _require_aws_cli():
    """Skip integration tests if the aws CLI is not on PATH."""
    if shutil.which("aws") is None:
        pytest.skip("aws CLI is not installed or not on PATH")


def _aws_env_args(config: IntegrationConfig) -> list[str]:
    args = []
    if config.profile:
        args += ["--profile", config.profile]
    if config.region:
        args += ["--region", config.region]
    return args


class AwsCli:
    def __init__(self, config: IntegrationConfig) -> None:
        self._config = config

    def run(self, *args: str) -> subprocess.CompletedProcess:
        cmd = ["aws", *_aws_env_args(self._config), *args]
        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    def run_json(self, *args: str) -> Any:
        return json.loads(self.run(*args, "--output", "json").stdout)


class R53Cli:
    def __init__(self, config: IntegrationConfig, repo_root: Path) -> None:
        self._config = config
        self._repo_root = repo_root

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        cmd = [
            "uv", "run", "r53.py",
            *( ["--profile", self._config.profile] if self._config.profile else [] ),
            *( ["--region", self._config.region] if self._config.region else [] ),
            *args,
        ]
        return subprocess.run(cmd, cwd=self._repo_root, check=check, capture_output=True, text=True)


@pytest.fixture(scope="session")
def aws_cli(integration_config) -> AwsCli:
    return AwsCli(integration_config)


@pytest.fixture(scope="session")
def r53_cli(integration_config) -> R53Cli:
    repo_root = Path(__file__).resolve().parents[2]
    return R53Cli(integration_config, repo_root)


@pytest.fixture(scope="session", autouse=True)
def _cleanup_before_session(integration_config):
    """Sweep any leftover r53-itest-* records before the session starts."""
    deleted = sweep(integration_config)
    if deleted:
        logger.info("Pre-session cleanup removed: %s", deleted)


@pytest.fixture(autouse=True)
def cleanup_after_each_test(integration_config):
    """Autouse teardown — remove any r53-itest-* records after each test."""
    yield
    deleted = sweep(integration_config)
    if deleted:
        logger.info("Post-test cleanup removed: %s", deleted)


@pytest.fixture
def itest_record_name(integration_config):
    """Return a function that builds fully-qualified test record names.

    Usage:
        def test_foo(itest_record_name):
            name = itest_record_name("lifecycle")  # -> r53-itest-lifecycle-<nonce>
    """
    def _make(scenario: str) -> str:
        nonce = uuid.uuid4().hex[:8]
        return f"r53-itest-{scenario}-{nonce}"
    return _make


@pytest.fixture(scope="session")
def zone_id(integration_config, aws_cli) -> str:
    """Resolve zone ID once per session from the configured domain."""
    data = aws_cli.run_json("route53", "list-hosted-zones")
    target = integration_config.domain.rstrip(".") + "."
    for zone in data.get("HostedZones", []):
        if zone["Name"] == target:
            return zone["Id"].split("/")[-1]
    pytest.fail(
        f"Zone {integration_config.domain} not found in Route 53 account "
        f"({'profile ' + integration_config.profile if integration_config.profile else 'default profile'})."
    )
