"""Integration tests — drive r53.py as a subprocess, verify via aws CLI."""

from __future__ import annotations


def _find_rrset(aws_cli, zone_id: str, record_name: str) -> dict | None:
    data = aws_cli.run_json(
        "route53", "list-resource-record-sets", "--hosted-zone-id", zone_id
    )
    target = record_name.rstrip(".") + "."
    for rr in data.get("ResourceRecordSets", []):
        if rr["Name"] == target:
            return rr
    return None


def test_a_record_full_lifecycle(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    short_name = itest_record_name("a-lifecycle")
    fqdn = f"{short_name}.{integration_config.domain}"

    # UPSERT
    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--type", "A",
        "--value", "192.0.2.10",
        "--ttl", "60",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None, f"record {fqdn} not created"
    assert rr["Type"] == "A"
    assert rr["TTL"] == 60
    assert [v["Value"] for v in rr["ResourceRecords"]] == ["192.0.2.10"]

    # UPDATE value + TTL (UPSERT with new value)
    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--type", "A",
        "--value", "192.0.2.11",
        "--ttl", "120",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None
    assert rr["TTL"] == 120
    assert [v["Value"] for v in rr["ResourceRecords"]] == ["192.0.2.11"]

    # DELETE
    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--type", "A",
        "--delete",
    )
    assert _find_rrset(aws_cli, zone_id, fqdn) is None
