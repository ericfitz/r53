"""Shared pytest fixtures for unit tests.

Provides stubbed boto3 clients for Route 53 and EC2 using
botocore.stub.Stubber, so unit tests make no network calls.
"""

import pytest
import boto3
from botocore.stub import Stubber


@pytest.fixture
def stubbed_route53():
    """Yield a (client, stubber) tuple for a stubbed Route 53 client.

    Tests queue expected API calls on the stubber before calling code
    under test.
    """
    client = boto3.client("route53", region_name="us-east-1")
    with Stubber(client) as stubber:
        yield client, stubber


@pytest.fixture
def stubbed_ec2():
    """Yield a (client, stubber) tuple for a stubbed EC2 client."""
    client = boto3.client("ec2", region_name="us-east-1")
    with Stubber(client) as stubber:
        yield client, stubber
