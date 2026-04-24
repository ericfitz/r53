#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "boto3>=1.35.81",
# ]
# ///

"""
r53.py

This script is a command-line tool for managing AWS Route 53 DNS records.

It allows users to perform various operations on Route 53 hosted zones
and resource records using the AWS API.

Features:
- List all hosted zones in your AWS account.
- List all resource records in a specified hosted zone.
- Retrieve details of a specific resource record in a hosted zone.
- Add or update resource records in a hosted zone.
- Delete a specific resource record from a hosted zone.
- Update a DNS record with the public IP address of the host running the script
  or an EC2 instance's public IP address.

Limitations:
- CREATE/UPSERT/DELETE operations only support standard resource records
  (A, AAAA, CNAME, MX, TXT, etc.) and do not support alias records.
- Alias records (pointing to ELBs, CloudFront distributions, S3 websites, etc.)
  can be listed and viewed but cannot be created, modified, or deleted.
- Weighted, latency-based, geolocation, and failover routing policies are not supported.
- Multi-value answer records can be listed but cannot be deleted via this tool.

Dependencies:
- boto3: AWS SDK for Python (automatically installed by uv)
- botocore: Low-level AWS SDK dependency
- re: Regular expressions for pattern matching
- socket: For network-related operations
- urllib: For making HTTP requests
- sys: For system-specific parameters and exit codes
- logging: For logging messages

Usage:
    uv run r53.py [options]

    Or with manual Python environment:
    python r53.py [options]

Author:
    Eric Fitzgerald (https://github.com/ericfitz)
"""

import argparse
import re
import socket
from dataclasses import dataclass
from typing import Any, Optional
from urllib import request, error
import sys
import logging
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)
import boto3


@dataclass
class Clients:
    """Bundle of boto3 clients used by this script."""
    route53: Any
    ec2: Any

# set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)


def get_instance_ip(instance_id: str, ec2: Any) -> str:
    """
    Given an instance id, returns the public IP address of that instance.

    :param instance_id: EC2 instance ID
    :param ec2: boto3 EC2 client
    :return: str, the public IPv4 address of the instance
    :raises ValueError: if instance has no public IP or instance not found
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        raise RuntimeError(
            f"ec2:DescribeInstances failed for {instance_id}: {e}"
        ) from e

    # Check if any reservations exist
    if not response.get("Reservations"):
        raise ValueError(f"No reservations found for instance ID: {instance_id}")

    # Search for the first public IP address
    for r in response["Reservations"]:
        for i in r.get("Instances", []):
            # Check if PublicIpAddress field exists
            if "PublicIpAddress" in i:
                ip_address = i["PublicIpAddress"]
                # Validate the IP address format
                if not is_valid_ipv4_address(ip_address):
                    raise ValueError(
                        f"Instance {instance_id} returned invalid IP address: {ip_address}"
                    )
                return ip_address

    # No public IP found
    raise ValueError(
        f"Instance {instance_id} does not have a public IP address. "
        "Ensure the instance is running and has a public IP assigned."
    )


def get_ip_from_eip(eip_allocation_id: str, ec2: Any) -> str:
    """
    Given an Elastic IP Allocation Id, returns the public IP address of that Elastic IP address.

    :param eip_allocation_id: EIP allocation ID (e.g., 'eipalloc-xxxxx')
    :param ec2: boto3 EC2 client
    :return: str, the public IPv4 address associated with the EIP
    :raises ValueError: if EIP allocation ID is invalid or not found
    """
    try:
        response = ec2.describe_addresses(AllocationIds=[eip_allocation_id])
    except ClientError as e:
        raise RuntimeError(
            f"ec2:DescribeAddresses failed for {eip_allocation_id}: {e}"
        ) from e

    # Check if any addresses were returned
    addresses = response.get("Addresses", [])
    if not addresses:
        raise ValueError(
            f"No Elastic IP found for allocation ID: {eip_allocation_id}"
        )

    # Get the first address
    ip_address = addresses[0].get("PublicIp")
    if not ip_address:
        raise ValueError(
            f"Elastic IP allocation {eip_allocation_id} does not have a public IP address"
        )

    # Validate the IP address format
    if not is_valid_ipv4_address(ip_address):
        raise ValueError(
            f"EIP {eip_allocation_id} returned invalid IP address: {ip_address}"
        )

    return ip_address


def get_my_ip() -> str:
    """
    Get the public IP address of the host running this script.

    The value is obtained from AWS's public IP address service.

    Returns:
        str: the public IP address of this host.
    """
    try:
        with request.urlopen("https://checkip.amazonaws.com") as f:
            return f.read().decode("utf-8").strip()
    except (error.URLError, error.HTTPError, socket.error) as e:
        raise RuntimeError(f"Error retrieving public IP address: {e}") from e


# https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address: str) -> bool:
    """
    Validate an IP address.

    Given a string, this function checks if that string is a valid IPv4 address
    in dotted quad format.

    :param address: a string to be validated as an IPv4 address
    :return: True if the address is valid, False otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        # https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
        re_ipv4 = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        return bool(re_ipv4.match(address))
    except socket.error:  # not a valid address
        return False
    except TypeError:
        return False
    return True


def is_valid_ipv6_address(address: str) -> bool:
    """
    Validate an IPv6 address.

    Given a string, this function checks if that string is a valid IPv6 address.

    :param address: A string to be validated as an IPv6 address
    :return: True if the address is valid, False otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    except TypeError:
        return False
    return True


# https://stackoverflow.com/questions/2532053/validate-a-hostname-string
def is_valid_dns_name(dns_name: str) -> bool:
    """
    Validate a DNS name.

    Given a string, this function checks if that string is a valid DNS name.
    A valid DNS name must be 255 characters or fewer, and each label within
    the name must be 63 characters or fewer. The function also allows for
    the presence of a trailing dot, which is stripped before validation.

    :param dns_name: A string to be validated as a DNS name
    :return: True if the DNS name is valid, False otherwise
    """
    try:
        if len(dns_name) > 255:
            return False
        if not dns_name:
            return False
        if dns_name[-1] == ".":
            dns_name = dns_name[
                :-1
            ]  # strip exactly one dot from the right, if present
        allowed = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",  # noqa: E501 - do not split regex across lines
            re.IGNORECASE,
        )
    except TypeError:
        return False
    validated_dns_name = allowed.match(dns_name)
    return validated_dns_name is not None


def is_valid_hostname(hostname: str) -> bool:
    """
    Validate a hostname.

    Given a string, this function checks if that string is a valid hostname.
    A valid hostname must consist of one or more labels separated by periods,
    where each label may contain alphanumeric characters and hyphens, but must
    not start or end with a hyphen. Each label must be between 1 and 63 characters,
    and the entire hostname must not exceed 255 characters.

    :param hostname: A string to be validated as a hostname
    :return: True if the hostname is valid, False otherwise
    """
    try:
        allowed = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",  # noqa: E501 - do not split regex across lines
            re.IGNORECASE,
        )
        return allowed.match(hostname) is not None
    except TypeError:
        return False


def get_hosted_zone_id_from_name(domain_name: str, route53: Any) -> Optional[str]:
    """
    Retrieve the hosted zone ID for a given domain name.

    This function iterates over all hosted zones in Route 53 and compares their
    names to the provided domain name. If a match is found, it returns the
    corresponding hosted zone ID. If no match is found, it returns None.

    :param domain_name: The domain name to search for in Route 53 hosted zones.
    :param route53: boto3 Route 53 client
    :return: The hosted zone ID if found, otherwise None.
    """
    try:
        paginator = route53.get_paginator("list_hosted_zones")
        response_iterator = paginator.paginate()
        for response in response_iterator:
            zones = response["HostedZones"]
            for zone in zones:
                zone_id = (zone["Id"].split("/")[-1:])[0]
                # 1. split by / into a list of strings
                # 2. get list of last string only
                # 3. convert list to string
                current_zone_name = zone["Name"].rstrip(".")  # remove trailing .
                if current_zone_name == domain_name:
                    return zone_id
        return None
    except ClientError as e:
        raise RuntimeError(
            f"route53:ListHostedZones failed while resolving {domain_name}: {e}"
        ) from e


def list_hosted_zones(route53: Any) -> None:
    """
    List all hosted zones in Route 53.

    This function iterates over all hosted zones in Route 53 and prints out each
    zone's ID and name.

    :param route53: boto3 Route 53 client
    :return: None
    """
    try:
        paginator = route53.get_paginator("list_hosted_zones")
        response_iterator = paginator.paginate()
        for response in response_iterator:
            zones = response["HostedZones"]
            for zone in zones:
                zone_id = (zone["Id"].split("/")[-1:])[0]
                zone_name = zone["Name"].rstrip(".")
                print(zone_id, zone_name)
    except ClientError as e:
        raise RuntimeError(f"route53:ListHostedZones failed: {e}") from e


def get_current_record(zone_id: str, record_name: str, route53: Any) -> dict:
    """
    Retrieve the current record details for a given record name in a specified hosted zone.

    This function uses the AWS Route 53 API to paginate through resource record sets
    within a specified hosted zone. It searches for a record set that matches the given
    record name and returns its details, including name, type, TTL, and values.

    :param zone_id: The ID of the hosted zone to search in.
    :param record_name: The name of the record to retrieve details for.
    :param route53: boto3 Route 53 client
    :return: A dictionary containing the record details if found, otherwise an empty dictionary.
             For standard records, "Values" will be a list of all values.
             For alias records, "AliasTarget" will contain alias details.
    """
    result = {}

    try:
        paginator = route53.get_paginator("list_resource_record_sets")
        response_iterator = paginator.paginate(
            HostedZoneId=zone_id, StartRecordName=record_name
        )
        for response in response_iterator:
            rrsets = response["ResourceRecordSets"]
            for rrset in rrsets:
                rrset_name = rrset["Name"].rstrip(".")
                if record_name == rrset_name:
                    result["Name"] = rrset_name
                    result["Type"] = rrset["Type"]

                    # Handle standard records with ResourceRecords
                    if "ResourceRecords" in rrset:
                        result["TTL"] = rrset["TTL"]
                        # Collect all values into a list
                        result["Values"] = [rr["Value"] for rr in rrset["ResourceRecords"]]

                    # Handle alias records
                    elif "AliasTarget" in rrset:
                        result["AliasTarget"] = rrset["AliasTarget"]

                    return result
    except ClientError as e:
        raise RuntimeError(
            f"route53:ListResourceRecordSets failed for zone {zone_id}: {e}"
        ) from e
    return result


def list_rr(zone_id: str, record_name: str, route53: Any) -> None:
    """
    List resource record sets for a specific record name within a given hosted zone.

    This function uses the AWS Route 53 API to paginate through resource record sets
    in a specified hosted zone, starting from a given record name. It prints the
    details of each record set, including the name, type, and value(s). For standard
    records, it displays TTL and resource record values. For alias records (e.g., ELB,
    CloudFront), it displays the alias target information.

    :param zone_id: The ID of the hosted zone to search in.
    :param record_name: The name of the record to start listing from.
    :param route53: boto3 Route 53 client
    :return: None
    """
    try:
        paginator = route53.get_paginator("list_resource_record_sets")
        response_iterator = paginator.paginate(
            HostedZoneId=zone_id, StartRecordName=record_name
        )
        for response in response_iterator:
            rrsets = response["ResourceRecordSets"]
            for rrset in rrsets:
                rrset_name = rrset["Name"].rstrip(".")

                # Handle standard records with ResourceRecords
                if "ResourceRecords" in rrset:
                    rrs = rrset["ResourceRecords"]
                    for rr in rrs:
                        print(
                            "Name: {}, Type: {}, TTL: {}, Value: {}".format(
                                rrset_name, rrset["Type"], rrset["TTL"], rr["Value"]
                            )
                        )

                # Handle alias records (ELB, CloudFront, etc.)
                elif "AliasTarget" in rrset:
                    alias = rrset["AliasTarget"]
                    print(
                        "Name: {}, Type: {}, Alias: {} (HostedZoneId: {}, EvaluateTargetHealth: {})".format(
                            rrset_name,
                            rrset["Type"],
                            alias["DNSName"].rstrip("."),
                            alias["HostedZoneId"],
                            alias.get("EvaluateTargetHealth", "N/A")
                        )
                    )

                # Handle unexpected record format
                else:
                    logger.warning(
                        "Unknown record format for %s (Type: %s). Record details: %s",
                        rrset_name,
                        rrset.get("Type", "UNKNOWN"),
                        rrset
                    )
    except ClientError as e:
        raise RuntimeError(
            f"route53:ListResourceRecordSets failed for zone {zone_id}: {e}"
        ) from e


def change_rr(
    action: str,
    zone_id: str,
    record_type: str,
    record_name: str,
    value: str,
    ttl: int,
    route53: Any,
) -> dict:
    """
    Update a resource record set in a specified hosted zone.

    This function uses the AWS Route 53 API to update a resource record set in a
    specified hosted zone. The function takes in parameters for the action to
    perform (CREATE, UPSERT, DELETE), the ID of the hosted zone, the type of the
    record, the name of the record, the new value of the record, and the TTL of
    the record. It returns the response from the AWS API.

    IMPORTANT: This function only supports standard resource records with a single
    value. It does NOT support:
    - Alias records (e.g., pointing to ELB, CloudFront, S3)
    - Weighted routing policy records
    - Latency-based routing policy records
    - Geolocation routing policy records
    - Failover routing policy records
    - Multi-value answer routing (only single values supported)

    To manage alias records or advanced routing policies, use the AWS Console or
    AWS CLI directly.

    :param action: The action to perform (CREATE, UPSERT, DELETE)
    :param zone_id: The ID of the hosted zone to update
    :param record_type: The type of the record to update (A, AAAA, MX, etc.)
    :param record_name: The name of the record to update
    :param value: The new value of the record
    :param ttl: The TTL of the record
    :param route53: boto3 Route 53 client
    :return: The response from the AWS API
    """
    try:
        response = route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "r53.py",
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": record_type,
                            "TTL": ttl,
                            "ResourceRecords": [
                                {"Value": value},
                            ],
                        },
                    },
                ],
            },
        )
    except ClientError as e:
        raise RuntimeError(
            f"route53:ChangeResourceRecordSets {action} failed for "
            f"{record_name} in zone {zone_id}: {e}"
        ) from e
    return response


####################################################################################################
# Begin main script
####################################################################################################

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="r53", description="Manage resource records in AWS Route 53"
    )
    parser.add_argument(
        "--profile",
        action="store",
        help="Use the specified AWS configuration profile instead of the default profile.",
    )
    parser.add_argument(
        "--region",
        action="store",
        help="Targets AWS API calls against the specified region instead of the default region in AWS configuration.",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete a resource record from a zone.",
    )
    parser.add_argument("--zone", action="store", help="DNS name of target zone")
    parser.add_argument("--name", action="store", help="name of resource record")
    parser.add_argument(
        "--type",
        action="store",
        help="Specifies the DNS resource record type",
        choices=["A", "AAAA", "CAA", "CNAME", "MX", "NAPTR", "NS", "PTR", "SOA", "SPF", "SRV", "TXT"],
    )
    parser.add_argument(
        "--ttl", action="store", type=int, default=300, help="TTL (in seconds, 0-2147483647)"
    )
    parser.add_argument(
        "--value", action="store", help="Specifies the value to set in the resource record"
    )
    parser.add_argument(
        "--eip",
        action="store",
        help="Sets value to the IP address associated with the specified EIP. Type and value parameters are ignored if EIP is specified.",
    )
    parser.add_argument(
        "--myip",
        action="store_true",
        help="Uses the calling computer's public IP address. Type and value parameters are ignored if --myip is specified.",
    )
    # noinspection SpellCheckingInspection,SpellCheckingInspection
    parser.add_argument(
        "--instanceid",
        action="store",
        help="Sets value to the public IP address of the specified EC2 instance. Type and value parameters are ignored if instance ID is specified.",
    )
    return parser.parse_args(argv)


def build_clients(profile: Optional[str], region: Optional[str]) -> Clients:
    """Initialize boto3 session and clients. Raises on failure."""
    if profile is not None:
        logger.info("Using AWS profile: %s", profile)
        try:
            boto3.setup_default_session(profile_name=profile)
        except ProfileNotFound as e:
            raise RuntimeError(f"AWS profile '{profile}' not found: {e}") from e

    try:
        route53 = boto3.client("route53")
        if region is not None:
            logger.info("Using AWS region: %s", region)
            ec2 = boto3.client("ec2", region_name=region)
        else:
            ec2 = boto3.client("ec2")
    except (BotoCoreError, NoCredentialsError, NoRegionError) as e:
        raise RuntimeError(f"Failed to create AWS client: {e}") from e

    return Clients(route53=route53, ec2=ec2)


def resolve_value(args: argparse.Namespace, ec2: Any) -> Optional[str]:
    """Resolve the record value from --value/--eip/--myip/--instanceid.

    Returns the resolved value (possibly None) and validates that at most one
    source was specified.
    """
    sources = [args.value, args.eip, args.instanceid]
    num_specified = sum(1 for s in sources if s is not None) + (1 if args.myip else 0)
    if num_specified > 1:
        raise ValueError("Specify only one of value, eip, myip, or instanceid")

    if args.eip is not None:
        value = get_ip_from_eip(args.eip, ec2)
        logger.debug("Calculated value from eip: %s", value)
        return value
    if args.myip:
        value = get_my_ip()
        logger.debug("Calculated value from IP lookup: %s", value)
        return value
    if args.instanceid is not None:
        value = get_instance_ip(args.instanceid, ec2)
        logger.debug("Calculated value from EC2 instance ID: %s", value)
        return value
    return args.value


def infer_record_type(explicit_type: Optional[str], value: Optional[str]) -> Optional[str]:
    """Infer the DNS record type from the value if not explicitly given."""
    if explicit_type is not None:
        return explicit_type
    if value is None:
        logger.debug("No value provided, type inference skipped")
        return None
    if is_valid_ipv4_address(value):
        inferred = "A"
    elif is_valid_ipv6_address(value):
        inferred = "AAAA"
    elif is_valid_dns_name(value):
        inferred = "CNAME"
    else:
        raise ValueError(
            f"Cannot infer record type from value '{value}'. "
            "Please specify --type explicitly."
        )
    logger.info("Inferred record type: %s", inferred)
    return inferred


def resolve_zone_id(zone_name: Optional[str], route53: Any) -> Optional[str]:
    """Look up the Route 53 zone ID for a zone name, or raise if not found."""
    if zone_name is None:
        return None
    if not is_valid_dns_name(zone_name):
        raise ValueError(f"Invalid zone name: {zone_name}")
    zone_id = get_hosted_zone_id_from_name(zone_name, route53)
    if zone_id is None:
        raise ValueError(
            f"Zone '{zone_name}' not found in Route 53. "
            "Use 'r53' without arguments to list available zones."
        )
    logger.debug("Matched zone name %s to zone ID %s", zone_name, zone_id)
    return zone_id


def determine_action(
    zone_id: Optional[str],
    record_name: Optional[str],
    record_type: Optional[str],
    value: Optional[str],
    delete: bool,
) -> str:
    """Decide which action to perform based on the argument combination.

    Logic is described in README.md file
    """
    if zone_id is None:
        return "LISTZONES"
    if record_name is None:
        return "LIST"
    if record_type is None:
        return "DESCRIBE"
    if value is None:
        if delete:
            return "DELETE"
        raise ValueError("Must specify value for upserts")
    return "UPSERT"


def execute_delete(zone_id: str, record_name: str, record_type: str, route53: Any) -> None:
    """Delete a record after verifying it exists, is not an alias, and is single-valued."""
    current_record = get_current_record(zone_id, record_name, route53)

    if not current_record:
        raise ValueError(f"Cannot delete nonexistent record: {record_name}")

    if "AliasTarget" in current_record:
        raise ValueError(
            f"Cannot delete alias record: {record_name}. "
            "Alias records must be deleted via AWS Console or AWS CLI."
        )

    values = current_record.get("Values", [])
    if len(values) > 1:
        raise ValueError(
            f"Record {record_name} has {len(values)} values: {', '.join(values)}. "
            "Multi-value record deletion is not supported. "
            "Use AWS Console or AWS CLI to delete this record."
        )

    value = values[0]
    logger.debug(
        "Executing action: action:DELETE zoneid:%s recordname:%s value:%s ttl:%s",
        zone_id, record_name, value, current_record["TTL"],
    )
    change_rr("DELETE", zone_id, record_type, record_name, value, current_record["TTL"], route53)


def main(argv: Optional[list[str]] = None, clients: Optional[Clients] = None) -> None:
    args = parse_args(argv)
    logger.debug("Arguments: %s", str(args))

    if args.ttl < 0 or args.ttl > 2147483647:
        raise ValueError(
            f"TTL must be between 0 and 2147483647 seconds, got: {args.ttl}"
        )

    if clients is None:
        clients = build_clients(args.profile, args.region)

    value = resolve_value(args, clients.ec2)
    record_type = infer_record_type(args.type, value)
    zone_id = resolve_zone_id(args.zone, clients.route53)

    record_name = args.name
    if record_name is not None and args.zone is not None:
        record_name = f"{args.name}.{args.zone}"
        logger.debug("Concatenated record name: %s", record_name)

    action = determine_action(zone_id, record_name, record_type, value, args.delete)
    logger.info("Inferred action: %s", action)

    # determine_action returns LIST/DESCRIBE/UPSERT/DELETE only when their
    # required fields are non-None; these asserts narrow Optional[...] for
    # the type checker and document the invariant.
    match action:
        case "LISTZONES":
            logger.debug("Executing action: action:%s", action)
            list_hosted_zones(clients.route53)
        case "LIST":
            assert zone_id is not None
            logger.debug("Executing action: action:%s zoneid:%s", action, zone_id)
            list_rr(zone_id, ".", clients.route53)
        case "DESCRIBE":
            assert zone_id is not None and record_name is not None
            logger.debug(
                "Executing action: action:%s zoneid:%s recordname:%s",
                action, zone_id, record_name,
            )
            list_rr(zone_id, record_name, clients.route53)
        case "UPSERT":
            assert (
                zone_id is not None
                and record_name is not None
                and record_type is not None
                and value is not None
            )
            logger.debug(
                "Executing action: action:%s zoneid:%s recordname:%s value:%s ttl:%s",
                action, zone_id, record_name, value, args.ttl,
            )
            change_rr(action, zone_id, record_type, record_name, value, args.ttl, clients.route53)
        case "DELETE":
            assert (
                zone_id is not None
                and record_name is not None
                and record_type is not None
            )
            execute_delete(zone_id, record_name, record_type, clients.route53)
        case _:
            raise ValueError("Invalid parameter combination and/or values.")

    logger.info("Success")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, ClientError, BotoCoreError) as e:
        logger.error("%s", e)
        sys.exit(1)

