"""Cleanup logic for integration-test records.

Sweeps any records matching the r53-itest- prefix in the configured zone.
Used by both the autouse pytest fixture and the standalone cleanup script.

Uses the aws CLI (via subprocess) rather than boto3 so the cleanup path
is independent of r53.py — even if r53.py is broken, cleanup still works.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Optional

from .config import IntegrationConfig


RECORD_PREFIX = "r53-itest-"


logger = logging.getLogger(__name__)


def _aws_env_args(config: IntegrationConfig) -> list[str]:
    args = []
    if config.profile:
        args += ["--profile", config.profile]
    if config.region:
        args += ["--region", config.region]
    return args


def _run_aws(config: IntegrationConfig, *aws_args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["aws", *_aws_env_args(config), *aws_args]
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def _lookup_zone_id(config: IntegrationConfig) -> Optional[str]:
    """Return the Route 53 hosted-zone ID for config.domain, or None if not found."""
    proc = _run_aws(config, "route53", "list-hosted-zones", "--output", "json")
    data = json.loads(proc.stdout)
    target = config.domain.rstrip(".") + "."
    for zone in data.get("HostedZones", []):
        if zone["Name"] == target:
            return zone["Id"].split("/")[-1]
    return None


def _list_itest_records(config: IntegrationConfig, zone_id: str) -> list[dict]:
    """Return resource-record-set dicts whose name starts with the test prefix."""
    proc = _run_aws(
        config,
        "route53",
        "list-resource-record-sets",
        "--hosted-zone-id",
        zone_id,
        "--output",
        "json",
    )
    data = json.loads(proc.stdout)
    out = []
    for rr in data.get("ResourceRecordSets", []):
        name = rr["Name"].rstrip(".")
        # match bare label or label followed by '.<domain>'
        first_label = name.split(".", 1)[0]
        if first_label.startswith(RECORD_PREFIX):
            out.append(rr)
    return out


def _delete_record(config: IntegrationConfig, zone_id: str, rrset: dict) -> None:
    change_batch = {
        "Comment": "r53-itest cleanup",
        "Changes": [{"Action": "DELETE", "ResourceRecordSet": rrset}],
    }
    proc = _run_aws(
        config,
        "route53",
        "change-resource-record-sets",
        "--hosted-zone-id",
        zone_id,
        "--change-batch",
        json.dumps(change_batch),
        check=False,
    )
    if proc.returncode != 0:
        # Idempotent: treat "no record" errors as success
        msg = proc.stderr or proc.stdout
        if "not found" in msg.lower() or "no such" in msg.lower():
            logger.info("Record %s already gone during cleanup", rrset.get("Name"))
            return
        raise RuntimeError(f"Failed to delete {rrset.get('Name')}: {msg}")


def sweep(config: IntegrationConfig) -> list[str]:
    """Delete all records matching the test prefix in the configured zone.

    Returns a list of record names that were deleted.
    """
    zone_id = _lookup_zone_id(config)
    if zone_id is None:
        logger.warning("Zone %s not found; nothing to clean up", config.domain)
        return []

    deleted: list[str] = []
    for rrset in _list_itest_records(config, zone_id):
        _delete_record(config, zone_id, rrset)
        deleted.append(rrset["Name"].rstrip("."))
    return deleted
