"""Unit tests for the AWS-calling functions in r53.py, using botocore Stubber."""

import pytest

from r53 import (
    change_rr,
    get_current_record,
    get_hosted_zone_id_from_name,
    get_instance_ip,
    get_ip_from_eip,
    list_hosted_zones,
    list_rr,
)


# ---------- get_instance_ip ----------

def test_get_instance_ip_happy_path(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-123", "PublicIpAddress": "1.2.3.4"},
                    ]
                }
            ]
        },
        expected_params={"InstanceIds": ["i-123"]},
    )

    assert get_instance_ip("i-123", client) == "1.2.3.4"


def test_get_instance_ip_no_reservations(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_instances",
        {"Reservations": []},
        expected_params={"InstanceIds": ["i-404"]},
    )

    with pytest.raises(ValueError, match="No reservations found"):
        get_instance_ip("i-404", client)


def test_get_instance_ip_no_public_ip(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-789"}]}  # no PublicIpAddress
            ]
        },
        expected_params={"InstanceIds": ["i-789"]},
    )

    with pytest.raises(ValueError, match="does not have a public IP"):
        get_instance_ip("i-789", client)


def test_get_instance_ip_invalid_ip_format(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-123", "PublicIpAddress": "not-an-ip"}
                    ]
                }
            ]
        },
        expected_params={"InstanceIds": ["i-123"]},
    )

    with pytest.raises(ValueError, match="invalid IP address"):
        get_instance_ip("i-123", client)


def test_get_instance_ip_client_error(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_client_error(
        "describe_instances",
        service_error_code="InvalidInstanceID.NotFound",
        service_message="not found",
        expected_params={"InstanceIds": ["i-nope"]},
    )

    with pytest.raises(RuntimeError, match="ec2:DescribeInstances failed"):
        get_instance_ip("i-nope", client)


# ---------- get_ip_from_eip ----------

def test_get_ip_from_eip_happy_path(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_addresses",
        {"Addresses": [{"PublicIp": "5.6.7.8", "AllocationId": "eipalloc-abc"}]},
        expected_params={"AllocationIds": ["eipalloc-abc"]},
    )

    assert get_ip_from_eip("eipalloc-abc", client) == "5.6.7.8"


def test_get_ip_from_eip_no_addresses(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_addresses",
        {"Addresses": []},
        expected_params={"AllocationIds": ["eipalloc-missing"]},
    )

    with pytest.raises(ValueError, match="No Elastic IP found"):
        get_ip_from_eip("eipalloc-missing", client)


def test_get_ip_from_eip_no_public_ip(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_addresses",
        {"Addresses": [{"AllocationId": "eipalloc-abc"}]},
        expected_params={"AllocationIds": ["eipalloc-abc"]},
    )

    with pytest.raises(ValueError, match="does not have a public IP"):
        get_ip_from_eip("eipalloc-abc", client)


def test_get_ip_from_eip_invalid_ip(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_response(
        "describe_addresses",
        {"Addresses": [{"PublicIp": "bogus", "AllocationId": "eipalloc-abc"}]},
        expected_params={"AllocationIds": ["eipalloc-abc"]},
    )

    with pytest.raises(ValueError, match="invalid IP address"):
        get_ip_from_eip("eipalloc-abc", client)


def test_get_ip_from_eip_client_error(stubbed_ec2):
    client, stubber = stubbed_ec2
    stubber.add_client_error(
        "describe_addresses",
        service_error_code="InvalidAllocationID.NotFound",
        service_message="nope",
        expected_params={"AllocationIds": ["eipalloc-nope"]},
    )

    with pytest.raises(RuntimeError, match="ec2:DescribeAddresses failed"):
        get_ip_from_eip("eipalloc-nope", client)


# ---------- get_hosted_zone_id_from_name ----------

def test_get_hosted_zone_id_found_first_page(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_hosted_zones",
        {
            "HostedZones": [
                {"Id": "/hostedzone/Z1", "Name": "example.com.",
                 "CallerReference": "x",
                 "Config": {"PrivateZone": False}},
                {"Id": "/hostedzone/Z2", "Name": "other.com.",
                 "CallerReference": "y",
                 "Config": {"PrivateZone": False}},
            ],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100",
        },
    )

    assert get_hosted_zone_id_from_name("example.com", client) == "Z1"


def test_get_hosted_zone_id_found_second_page(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_hosted_zones",
        {
            "HostedZones": [
                {"Id": "/hostedzone/Z1", "Name": "other.com.",
                 "CallerReference": "a",
                 "Config": {"PrivateZone": False}},
            ],
            "Marker": "",
            "IsTruncated": True,
            "NextMarker": "Z1",
            "MaxItems": "1",
        },
    )
    stubber.add_response(
        "list_hosted_zones",
        {
            "HostedZones": [
                {"Id": "/hostedzone/Z2", "Name": "example.com.",
                 "CallerReference": "b",
                 "Config": {"PrivateZone": False}},
            ],
            "Marker": "Z1",
            "IsTruncated": False,
            "MaxItems": "1",
        },
        expected_params={"Marker": "Z1"},
    )

    assert get_hosted_zone_id_from_name("example.com", client) == "Z2"


def test_get_hosted_zone_id_not_found(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_hosted_zones",
        {
            "HostedZones": [
                {"Id": "/hostedzone/Z1", "Name": "other.com.",
                 "CallerReference": "x",
                 "Config": {"PrivateZone": False}},
            ],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100",
        },
    )

    assert get_hosted_zone_id_from_name("missing.com", client) is None


def test_get_hosted_zone_id_client_error(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_client_error(
        "list_hosted_zones",
        service_error_code="AccessDenied",
        service_message="no",
    )

    with pytest.raises(RuntimeError, match="route53:ListHostedZones failed"):
        get_hosted_zone_id_from_name("example.com", client)


# ---------- list_hosted_zones ----------

def test_list_hosted_zones_prints_zones(stubbed_route53, capsys):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_hosted_zones",
        {
            "HostedZones": [
                {"Id": "/hostedzone/Z1", "Name": "example.com.",
                 "CallerReference": "x",
                 "Config": {"PrivateZone": False}},
                {"Id": "/hostedzone/Z2", "Name": "other.com.",
                 "CallerReference": "y",
                 "Config": {"PrivateZone": False}},
            ],
            "Marker": "",
            "IsTruncated": False,
            "MaxItems": "100",
        },
    )

    list_hosted_zones(client)
    captured = capsys.readouterr()
    assert "Z1 example.com" in captured.out
    assert "Z2 other.com" in captured.out


def test_list_hosted_zones_client_error(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_client_error(
        "list_hosted_zones",
        service_error_code="Throttling",
        service_message="slow down",
    )

    with pytest.raises(RuntimeError, match="route53:ListHostedZones failed"):
        list_hosted_zones(client)


# ---------- get_current_record ----------

def _make_rrsets_response(rrsets):
    return {
        "ResourceRecordSets": rrsets,
        "IsTruncated": False,
        "MaxItems": "100",
    }


def test_get_current_record_standard_single_value(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_resource_record_sets",
        _make_rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "1.2.3.4"}],
                }
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "foo.example.com"},
    )

    assert get_current_record("Z1", "foo.example.com", client) == {
        "Name": "foo.example.com",
        "Type": "A",
        "TTL": 300,
        "Values": ["1.2.3.4"],
    }


def test_get_current_record_multi_value(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_resource_record_sets",
        _make_rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "1.2.3.4"}, {"Value": "5.6.7.8"}],
                }
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "foo.example.com"},
    )

    result = get_current_record("Z1", "foo.example.com", client)
    assert result["Values"] == ["1.2.3.4", "5.6.7.8"]


def test_get_current_record_alias(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_resource_record_sets",
        _make_rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "AliasTarget": {
                        "HostedZoneId": "Z0",
                        "DNSName": "elb.example.com.",
                        "EvaluateTargetHealth": False,
                    },
                }
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "foo.example.com"},
    )

    result = get_current_record("Z1", "foo.example.com", client)
    assert "TTL" not in result
    assert result["AliasTarget"]["DNSName"] == "elb.example.com."


def test_get_current_record_not_found(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_resource_record_sets",
        _make_rrsets_response(
            [
                {
                    "Name": "other.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "1.2.3.4"}],
                }
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "foo.example.com"},
    )

    assert get_current_record("Z1", "foo.example.com", client) == {}


def test_get_current_record_client_error(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_client_error(
        "list_resource_record_sets",
        service_error_code="NoSuchHostedZone",
        service_message="missing",
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "foo.example.com"},
    )

    with pytest.raises(RuntimeError, match="route53:ListResourceRecordSets failed"):
        get_current_record("Z1", "foo.example.com", client)


# ---------- list_rr ----------

def test_list_rr_standard_record(stubbed_route53, capsys):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_resource_record_sets",
        _make_rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": "1.2.3.4"}],
                }
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "."},
    )

    list_rr("Z1", ".", client)
    captured = capsys.readouterr()
    assert "Name: foo.example.com" in captured.out
    assert "Type: A" in captured.out
    assert "TTL: 300" in captured.out
    assert "Value: 1.2.3.4" in captured.out


def test_list_rr_alias_record(stubbed_route53, capsys):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_resource_record_sets",
        _make_rrsets_response(
            [
                {
                    "Name": "foo.example.com.",
                    "Type": "A",
                    "AliasTarget": {
                        "HostedZoneId": "Z0",
                        "DNSName": "elb.example.com.",
                        "EvaluateTargetHealth": True,
                    },
                }
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "."},
    )

    list_rr("Z1", ".", client)
    captured = capsys.readouterr()
    assert "Alias: elb.example.com" in captured.out
    assert "HostedZoneId: Z0" in captured.out
    assert "EvaluateTargetHealth: True" in captured.out


def test_list_rr_unknown_format_logs_warning(stubbed_route53, caplog):
    client, stubber = stubbed_route53
    stubber.add_response(
        "list_resource_record_sets",
        _make_rrsets_response(
            [
                {"Name": "weird.example.com.", "Type": "A"},
            ]
        ),
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "."},
    )

    import logging
    with caplog.at_level(logging.WARNING, logger="r53"):
        list_rr("Z1", ".", client)
    assert any("Unknown record format" in record.message for record in caplog.records)


def test_list_rr_client_error(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_client_error(
        "list_resource_record_sets",
        service_error_code="NoSuchHostedZone",
        service_message="missing",
        expected_params={"HostedZoneId": "Z1", "StartRecordName": "."},
    )

    with pytest.raises(RuntimeError, match="route53:ListResourceRecordSets failed"):
        list_rr("Z1", ".", client)


# ---------- change_rr ----------

def test_change_rr_happy_path_sends_expected_change_batch(stubbed_route53):
    client, stubber = stubbed_route53
    expected_params = {
        "HostedZoneId": "Z1",
        "ChangeBatch": {
            "Comment": "r53.py",
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": "foo.example.com",
                        "Type": "A",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": "1.2.3.4"}],
                    },
                }
            ],
        },
    }
    stubber.add_response(
        "change_resource_record_sets",
        {
            "ChangeInfo": {
                "Id": "/change/C1",
                "Status": "PENDING",
                "SubmittedAt": __import__("datetime").datetime(2026, 1, 1),
            }
        },
        expected_params=expected_params,
    )

    response = change_rr(
        "UPSERT", "Z1", "A", "foo.example.com", "1.2.3.4", 300, client
    )
    assert response["ChangeInfo"]["Status"] == "PENDING"


def test_change_rr_client_error(stubbed_route53):
    client, stubber = stubbed_route53
    stubber.add_client_error(
        "change_resource_record_sets",
        service_error_code="InvalidChangeBatch",
        service_message="bad",
    )

    with pytest.raises(RuntimeError, match="route53:ChangeResourceRecordSets UPSERT failed"):
        change_rr("UPSERT", "Z1", "A", "foo.example.com", "1.2.3.4", 300, client)
