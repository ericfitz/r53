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


def test_type_inference_ipv4_to_a(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    short_name = itest_record_name("infer-a")
    fqdn = f"{short_name}.{integration_config.domain}"

    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--value", "192.0.2.20",
        "--ttl", "60",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None
    assert rr["Type"] == "A"


def test_type_inference_ipv6_to_aaaa(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    short_name = itest_record_name("infer-aaaa")
    fqdn = f"{short_name}.{integration_config.domain}"

    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--value", "2001:db8::1",
        "--ttl", "60",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None
    assert rr["Type"] == "AAAA"


def test_type_inference_dns_name_to_cname(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    short_name = itest_record_name("infer-cname")
    fqdn = f"{short_name}.{integration_config.domain}"

    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--value", "target.example.com",
        "--ttl", "60",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None
    assert rr["Type"] == "CNAME"


def test_cname_full_lifecycle(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    short_name = itest_record_name("cname-lifecycle")
    fqdn = f"{short_name}.{integration_config.domain}"

    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--type", "CNAME",
        "--value", "first.example.com",
        "--ttl", "60",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None
    assert rr["Type"] == "CNAME"
    assert [v["Value"] for v in rr["ResourceRecords"]] == ["first.example.com"]

    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--type", "CNAME",
        "--value", "second.example.com",
        "--ttl", "90",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None
    assert rr["TTL"] == 90
    assert [v["Value"] for v in rr["ResourceRecords"]] == ["second.example.com"]

    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--type", "CNAME",
        "--delete",
    )
    assert _find_rrset(aws_cli, zone_id, fqdn) is None


def test_describe_record(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    """Create a record via aws-cli, DESCRIBE it via r53, assert output."""
    import json

    short_name = itest_record_name("describe")
    fqdn = f"{short_name}.{integration_config.domain}"

    # Create via aws CLI directly so this test exercises r53's read path.
    change_batch = {
        "Comment": "r53-itest describe setup",
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": fqdn,
                    "Type": "A",
                    "TTL": 60,
                    "ResourceRecords": [{"Value": "192.0.2.30"}],
                },
            }
        ],
    }
    aws_cli.run(
        "route53", "change-resource-record-sets",
        "--hosted-zone-id", zone_id,
        "--change-batch", json.dumps(change_batch),
    )

    proc = r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
    )
    assert fqdn in proc.stdout
    assert "Type: A" in proc.stdout
    assert "Value: 192.0.2.30" in proc.stdout


def test_list_records_in_zone(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    name_a = itest_record_name("list-a")
    name_b = itest_record_name("list-b")
    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", name_a,
        "--type", "A",
        "--value", "192.0.2.40",
        "--ttl", "60",
    )
    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", name_b,
        "--type", "A",
        "--value", "192.0.2.41",
        "--ttl", "60",
    )

    proc = r53_cli.run("--zone", integration_config.domain)
    assert f"{name_a}.{integration_config.domain}" in proc.stdout
    assert f"{name_b}.{integration_config.domain}" in proc.stdout


def test_list_hosted_zones(integration_config, r53_cli):
    proc = r53_cli.run()
    assert integration_config.domain in proc.stdout


def test_delete_nonexistent_record_fails(
    integration_config, r53_cli, itest_record_name
):
    short_name = itest_record_name("nonexistent")

    proc = r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--type", "A",
        "--delete",
        check=False,
    )
    assert proc.returncode != 0
    combined = proc.stdout + proc.stderr
    assert "Cannot delete nonexistent" in combined or "nonexistent" in combined.lower()


def test_myip_upsert(
    integration_config, r53_cli, aws_cli, zone_id, itest_record_name
):
    import socket
    from urllib import error, request
    import pytest

    try:
        with request.urlopen("https://checkip.amazonaws.com", timeout=5) as f:
            expected_ip = f.read().decode("utf-8").strip()
    except (error.URLError, error.HTTPError, socket.error):
        pytest.skip("Cannot reach checkip.amazonaws.com from this host")

    short_name = itest_record_name("myip")
    fqdn = f"{short_name}.{integration_config.domain}"

    r53_cli.run(
        "--zone", integration_config.domain,
        "--name", short_name,
        "--myip",
        "--ttl", "60",
    )
    rr = _find_rrset(aws_cli, zone_id, fqdn)
    assert rr is not None
    assert rr["Type"] == "A"
    assert [v["Value"] for v in rr["ResourceRecords"]] == [expected_ip]
