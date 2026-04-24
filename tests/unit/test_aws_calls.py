"""Unit tests for the AWS-calling functions in r53.py, using botocore Stubber."""

import pytest

from r53 import (
    get_instance_ip,
    get_ip_from_eip,
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
