#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
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
from urllib import request, error
import sys
import logging
from botocore.exceptions import ClientError
import boto3

# set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)


def get_instance_ip(instance_id):
    """
    Given an instance id, returns the public IP address of that instance.

    :param instance_id: EC2 instance ID
    :return: str, the public IPv4 address of the instance
    :raises ValueError: if instance has no public IP or instance not found
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        logger.error("AWS ec2-describe-instances error: %s", e)
        sys.exit()

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


def get_ip_from_eip(eip_allocation_id):
    """
    Given an Elastic IP Allocation Id, returns the public IP address of that Elastic IP address.

    :param eip_allocation_id: EIP allocation ID (e.g., 'eipalloc-xxxxx')
    :return: str, the public IPv4 address associated with the EIP
    :raises ValueError: if EIP allocation ID is invalid or not found
    """
    try:
        response = ec2.describe_addresses(AllocationIds=[eip_allocation_id])
    except ClientError as e:
        logger.error("AWS ec2-describe-addresses error: %s", e)
        sys.exit()

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


def get_my_ip():
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
        logger.error("Error retrieving public IP address: %s", e)
        sys.exit()


# https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address):
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


def is_valid_ipv6_address(address):
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
def is_valid_dns_name(dns_name):
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


def is_valid_hostname(hostname):
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


def get_hosted_zone_id_from_name(domain_name):
    """
    Retrieve the hosted zone ID for a given domain name.

    This function iterates over all hosted zones in Route 53 and compares their
    names to the provided domain name. If a match is found, it returns the
    corresponding hosted zone ID. If no match is found, it returns None.

    :param domain_name: The domain name to search for in Route 53 hosted zones.
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
        logger.error("AWS route53-list-hosted-zones error: %s", e)
        sys.exit()


def list_hosted_zones():
    """
    List all hosted zones in Route 53.

    This function iterates over all hosted zones in Route 53 and prints out each
    zone's ID and name.

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
        logger.error("AWS route53-list-hosted-zones error: %s", e)
        sys.exit()


def get_current_record(zone_id, record_name):
    """
    Retrieve the current record details for a given record name in a specified hosted zone.

    This function uses the AWS Route 53 API to paginate through resource record sets
    within a specified hosted zone. It searches for a record set that matches the given
    record name and returns its details, including name, type, TTL, and values.

    :param zone_id: The ID of the hosted zone to search in.
    :param record_name: The name of the record to retrieve details for.
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
        logger.error("AWS route53-list-resource-record-sets error: %s", e)
        sys.exit()
    return result


def list_rr(zone_id, record_name):
    """
    List resource record sets for a specific record name within a given hosted zone.

    This function uses the AWS Route 53 API to paginate through resource record sets
    in a specified hosted zone, starting from a given record name. It prints the
    details of each record set, including the name, type, and value(s). For standard
    records, it displays TTL and resource record values. For alias records (e.g., ELB,
    CloudFront), it displays the alias target information.

    :param zone_id: The ID of the hosted zone to search in.
    :param record_name: The name of the record to start listing from.
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
        logger.error("AWS route53-list-resource-record-sets error: %s", e)
        sys.exit()


def change_rr(action, zone_id, record_type, record_name, value, ttl):
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
        logger.error("AWS route53-change-resource-record-sets error: %s", e)
        sys.exit()
    return response


####################################################################################################
# Begin main script
####################################################################################################

# parse command line arguments
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
# default operation is list. If a value is specified, operation is upsert.  Delete must be explicit.
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

args = parser.parse_args()
logger.debug("Arguments: %s", str(args))

# set up the boto3 clients
if args.profile is not None:
    logger.info("Using AWS profile: %s", args.profile)
    try:
        boto3.setup_default_session(profile_name=args.profile)
    except ClientError as e:
        logger.error(
            "Boto error %s creating session using specified profile %s", e, args.profile
        )
        sys.exit()

# AWS Route 53 is global, not regional, so we can ignore region for Route 53 connection.
try:
    route53 = boto3.client("route53")
except ClientError as e:
    logger.error("Boto error %s creating Route 53 client", e)
    sys.exit()

# EC2 is regional, so we need to use region if specified
# r53 uses EC2 to look up instance IP addresses & EIPs
if args.region is not None:
    logger.info("Using AWS region: %s", args.region)
    try:
        ec2 = boto3.client("ec2", region_name=args.region)
    except ClientError as e:
        logger.error(
            "Boto error %s creating EC2 client in specified region %s", e, args.region
        )
        sys.exit()
else:
    try:
        ec2 = boto3.client("ec2")
    except ClientError as e:
        logger.error("Boto error %s creating EC2 client in default region", e)
        sys.exit()

# Validate and process the provided parameters
ZONE_NAME = args.zone
RECORD_NAME = args.name
RECORD_TYPE = args.type
value = args.value
eip = args.eip
myip = args.myip
instanceid = args.instanceid
ttl = args.ttl

# Validate TTL range per Route 53 constraints
if ttl < 0 or ttl > 2147483647:
    raise ValueError(
        f"TTL must be between 0 and 2147483647 seconds, got: {ttl}"
    )

# only allow one of (value, eip, myip, instanceid) to be specified
NUMVALUES = 0

if value is not None:
    NUMVALUES += 1

if eip is not None:
    NUMVALUES += 1
    try:
        value = get_ip_from_eip(args.eip)
        logger.debug("Calculated value from eip: %s", value)
    except ValueError as e:
        logger.error("Failed to retrieve IP from EIP: %s", e)
        sys.exit(1)

if myip:
    NUMVALUES += 1
    value = get_my_ip()
    logger.debug("Calculated value from IP lookup: %s", value)

if instanceid is not None:
    NUMVALUES += 1
    try:
        value = get_instance_ip(args.instanceid)
        logger.debug("Calculated value from EC2 instance ID: %s", value)
    except ValueError as e:
        logger.error("Failed to retrieve IP from instance: %s", e)
        sys.exit(1)

if NUMVALUES > 1:
    raise ValueError(
        "Specify only one of value, eip, myip, or instanceid"
    )  # only one of value, eip, myip, or instanceid can be specified

# figure out the record type if not explicitly specified
if RECORD_TYPE is None:
    # Only attempt type inference if a value exists
    if value is not None:
        if is_valid_ipv4_address(value):
            RECORD_TYPE = "A"
        elif is_valid_ipv6_address(value):
            RECORD_TYPE = "AAAA"
        elif is_valid_dns_name(value):
            RECORD_TYPE = "CNAME"
        else:
            raise ValueError(
                f"Cannot infer record type from value '{value}'. "
                "Please specify --type explicitly."
            )
        logger.info("Inferred record type: %s", RECORD_TYPE)
    else:
        # value is None - this is OK for DESCRIBE and LIST operations
        # but will be caught later if trying to UPSERT
        logger.debug("No value provided, type inference skipped")

# look up zone id if zone name provided
ZONE_ID = None
if ZONE_NAME is not None:
    if not is_valid_dns_name(args.zone):
        raise ValueError(f"Invalid zone name: {args.zone}")
    ZONE_ID = get_hosted_zone_id_from_name(args.zone)
    if ZONE_ID is None:
        raise ValueError(
            f"Zone '{args.zone}' not found in Route 53. "
            "Use 'r53' without arguments to list available zones."
        )
    logger.debug("Matched zone name %s to zone ID %s", ZONE_NAME, ZONE_ID)

# append the zone name to the record name if required
if RECORD_NAME is not None and ZONE_NAME is not None:
    RECORD_NAME = str(args.name) + "." + str(args.zone)
    logger.debug("Concatenated record name: %s", RECORD_NAME)

# figure out the action to take
# logic is described in Google sheet: https://bit.ly/r53params
if ZONE_ID is None:
    ACTION = "LISTZONES"
else:
    if RECORD_NAME is None:
        ACTION = "LIST"
    else:
        if RECORD_TYPE is None:
            ACTION = "DESCRIBE"
        else:
            if value is None:
                if args.delete:
                    ACTION = "DELETE"
                else:
                    raise ValueError("Must specify value for upserts")
            else:
                ACTION = "UPSERT"

if ACTION is None:
    raise ValueError(
        "Invalid parameter combination and/or values"
    )  # if we got here, there was a bug in the parameter validation code above
else:
    logger.info("Inferred action: %s", ACTION)

# execute the action
match ACTION:
    case "LISTZONES":
        logger.debug("Executing action: action:%s", ACTION)
        list_hosted_zones()
    case "LIST":
        logger.debug("Executing action: action:%s zoneid:%s", ACTION, ZONE_ID)
        list_rr(ZONE_ID, ".")
    case "DESCRIBE":
        logger.debug(
            "Executing action: action:%s zoneid:%s recordname:%s",
            ACTION,
            ZONE_ID,
            RECORD_NAME,
        )
        list_rr(ZONE_ID, RECORD_NAME)
    case "UPSERT":
        logger.debug(
            "Executing action: action:%s zoneid:%s recordname:%s value:%s ttl:%s",
            ACTION,
            ZONE_ID,
            RECORD_NAME,
            value,
            args.ttl,
        )
        change_rr(ACTION, ZONE_ID, RECORD_TYPE, RECORD_NAME, value, args.ttl)
    case "DELETE":
        current_record = get_current_record(ZONE_ID, RECORD_NAME)

        # Check if record exists
        if not current_record:
            logger.error("Cannot delete nonexistent record: %s", RECORD_NAME)
            sys.exit()

        # Check if this is an alias record
        if "AliasTarget" in current_record:
            logger.error(
                "Cannot delete alias record: %s. "
                "Alias records must be deleted via AWS Console or AWS CLI.",
                RECORD_NAME
            )
            sys.exit()

        # Check for multi-value records
        values = current_record.get("Values", [])
        if len(values) > 1:
            logger.error(
                "Record %s has %d values: %s",
                RECORD_NAME,
                len(values),
                ", ".join(values)
            )
            logger.error(
                "Multi-value record deletion is not supported. "
                "Use AWS Console or AWS CLI to delete this record."
            )
            sys.exit()

        value = values[0]

        logger.debug(
            "Executing action: action:%s zoneid:%s recordname:%s value:%s ttl:%s",
            ACTION,
            ZONE_ID,
            RECORD_NAME,
            value,
            current_record["TTL"],
        )

        try:
            change_rr(
                ACTION, ZONE_ID, RECORD_TYPE, RECORD_NAME, value, current_record["TTL"]
            )
        except ClientError as e:
            logger.error("Failed to delete record: %s", e)
            sys.exit()
    case _:
        raise ValueError(
            "Invalid parameter combination and/or values."
        )  # if we got here, there was a bug in the parameter validation code above

logger.info("Success")
