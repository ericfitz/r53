#!/usr/bin/env python3
import argparse
import re
import socket
import urllib.request as request
import boto3
import logging

# set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)


def get_instance_ip(instance_id):
    """
    Given an instance id, returns the public IP address of that instance.
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
    except Exception as e:
        logger.error("AWS ec2-escribe-instances error: {}".format(e))
        exit(1)
    # return the first public IP address found
    for r in response["Reservations"]:
        for i in r["Instances"]:
            return i["PublicIpAddress"]


def get_ip_from_eip(eip):
    """
    Given an Elastic IP Allocation Id, returns the public IP address of that Elastic IP address.
    """
    try:
        response = ec2.describe_addresses(AllocationIds=[eip])
    except Exception as e:
        logger.error("AWS ec2-describe-addresses error: {}".format(e))
        exit(1)
    # return the first public IP address found
    for a in response["Addresses"]:
        return a["PublicIp"]


def get_my_ip():
    """
    Get the public IP address of the host running this script.

    The value is obtained from AWS's public IP address service.

    Returns:
        str: the public IP address of this host.
    """
    with request.urlopen("https://checkip.amazonaws.com") as f:
        return f.read().decode("utf-8").strip()
    # todo: error handling


# https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address):
    """
    Validate an IP address.

    Given a string, this function checks if that string is a valid IPv4 address in dotted quad format.

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
        is_ipv4 = address == re_ipv4.match(address)
        return is_ipv4
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
def is_valid_dns_name(p_dns_name):
    """
    Validate a DNS name.

    Given a string, this function checks if that string is a valid DNS name.
    A valid DNS name must be 255 characters or fewer, and each label within
    the name must be 63 characters or fewer. The function also allows for
    the presence of a trailing dot, which is stripped before validation.

    :param p_dns_name: A string to be validated as a DNS name
    :return: True if the DNS name is valid, False otherwise
    """
    try:
        if len(p_dns_name) > 255:
            return False
        if p_dns_name[-1] == ".":
            p_dns_name = p_dns_name[
                :-1
            ]  # strip exactly one dot from the right, if present
        # noinspection PyPep8
        allowed = re.compile(
            r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\
(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$",
            re.IGNORECASE,
        )
    except TypeError:
        return False
    validated_dns_name = allowed.match(p_dns_name)
    return validated_dns_name


def is_valid_hostname(hostname):
    # noinspection PyPep8
    """
    Validate a hostname.

    Given a string, this function checks if that string is a valid hostname.
    A valid hostname must consist of one or more labels separated by periods,
    where each label may contain alphanumeric characters and hyphens, but must
    not start or end with a hyphen. Each label must be between 1 and 63 characters,
    and the entire hostname must not exceed 255 characters.

    :param hostname: A string to be validated as a hostname
    :return: A match object if the hostname is valid, None otherwise
    """
    allowed = re.compile(
        r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\
(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$",
        re.IGNORECASE,
    )
    return allowed.match(hostname)


def get_hosted_zone_id_from_name(p_domain_name):
    """
    Retrieve the hosted zone ID for a given domain name.

    This function iterates over all hosted zones in Route 53 and compares their
    names to the provided domain name. If a match is found, it returns the
    corresponding hosted zone ID. If no match is found, it returns None.

    :param p_domain_name: The domain name to search for in Route 53 hosted zones.
    :return: The hosted zone ID if found, otherwise None.
    """
    try:
        paginator = route53.get_paginator("list_hosted_zones")
        response_iterator = paginator.paginate()
        for response in response_iterator:
            zones = response["HostedZones"]
            for zone in zones:
                l_zone_id = (zone["Id"].split("/")[-1:])[0]
                # split by / into a list of strings, get list of last string only, convert list to string
                zone_name = zone["Name"].rstrip(".")  # remove trailing .
                if zone_name == p_domain_name:
                    return l_zone_id
        return None
    except Exception as e:
        logger.error("AWS route53-list-hosted-zones error: {}".format(e))
        exit(1)


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
                l_zone_id = (zone["Id"].split("/")[-1:])[0]
                l_zone_name = zone["Name"].rstrip(".")
                print(l_zone_id, l_zone_name)
        return None
    except Exception as e:
        logger.error("AWS route53-list-hosted-zones error: {}".format(e))
        exit(1)


def get_current_record(p_zone_id, p_record_name):
    """
    Retrieve the current record details for a given record name in a specified hosted zone.

    This function uses the AWS Route 53 API to paginate through resource record sets
    within a specified hosted zone. It searches for a record set that matches the given
    record name and returns its details, including name, type, TTL, and value.

    :param p_zone_id: The ID of the hosted zone to search in.
    :param p_record_name: The name of the record to retrieve details for.
    :return: A dictionary containing the record details if found, otherwise an empty dictionary.
    """
    result = {}

    try:
        paginator = route53.get_paginator("list_resource_record_sets")
        response_iterator = paginator.paginate(
            HostedZoneId=p_zone_id, StartRecordName=p_record_name
        )
        for response in response_iterator:
            rrsets = response["ResourceRecordSets"]
            for rrset in rrsets:
                rrset_name = rrset["Name"].rstrip(".")
                if p_record_name == rrset_name:
                    rrs = rrset["ResourceRecords"]
                    for rr in rrs:
                        result["Name"] = rrset_name
                        result["Type"] = rrset["Type"]
                        result["TTL"] = rrset["TTL"]
                        result["Value"] = rr["Value"]
    except Exception as e:
        logger.error("AWS route53-list-resource-record-sets error: {}".format(e))
        exit(1)
    return result


def list_rr(p_zone_id, p_record_name):
    """
    List resource record sets for a specific record name within a given hosted zone.

    This function uses the AWS Route 53 API to paginate through resource record sets
    in a specified hosted zone, starting from a given record name. It prints the
    details of each record set, including the name, type, TTL, and value. If a record
    set has an unexpected format, it prints the JSON representation of the record set.

    :param p_zone_id: The ID of the hosted zone to search in.
    :param p_record_name: The name of the record to start listing from.
    :return: None
    """
    try:
        paginator = route53.get_paginator("list_resource_record_sets")
        response_iterator = paginator.paginate(
            HostedZoneId=p_zone_id, StartRecordName=p_record_name
        )
        for response in response_iterator:
            rrsets = response["ResourceRecordSets"]
            for rrset in rrsets:
                rrset_name = rrset["Name"].rstrip(".")
                try:
                    rrs = rrset["ResourceRecords"]
                    for rr in rrs:
                        print(
                            "Name: {}, Type: {}, TTL: {}, Value: {}".format(
                                rrset_name, rrset["Type"], rrset["TTL"], rr["Value"]
                            )
                        )
                except (
                    KeyError
                ):  # A records for ELB have an odd format, just print the JSON for them
                    print(rrset)
    except Exception as e:
        logger.error("AWS route53-list-resource-record-sets error: {}".format(e))
        exit(1)
    return None


def change_rr(p_action, p_zone_id, p_record_type, p_record_name, p_value, p_ttl):
    """
    Update a resource record set in a specified hosted zone.

    This function uses the AWS Route 53 API to update a resource record set in a
    specified hosted zone. The function takes in parameters for the action to
    perform (CREATE, UPDATE, DELETE), the ID of the hosted zone, the type of the
    record, the name of the record, the new value of the record, and the TTL of
    the record. It returns the response from the AWS API.

    :param p_action: The action to perform (CREATE, UPDATE, DELETE)
    :param p_zone_id: The ID of the hosted zone to update
    :param p_record_type: The type of the record to update (A, AAAA, MX, etc.)
    :param p_record_name: The name of the record to update
    :param p_value: The new value of the record
    :param p_ttl: The TTL of the record
    :return: The response from the AWS API
    """
    try:
        response = route53.change_resource_record_sets(
            HostedZoneId=p_zone_id,
            ChangeBatch={
                "Comment": "r53.py",
                "Changes": [
                    {
                        "Action": p_action,
                        "ResourceRecordSet": {
                            "Name": p_record_name,
                            "Type": p_record_type,
                            "TTL": p_ttl,
                            "ResourceRecords": [
                                {"Value": p_value},
                            ],
                        },
                    },
                ],
            },
        )
    except Exception as e:
        logger.error("AWS route53-change-resource-record-sets error: {}".format(e))
        exit(1)
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
    choices=["A", "AAAA", "CAA", "CNAME", "MX", "NAPTR", "SPF", "SRV", "TXT"],
)
parser.add_argument(
    "--ttl", action="store", type=int, default=300, help="TTL (in seconds)"
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
logger.debug(f"Arguments: {str(args)}")

# set up the boto3 clients
if args.profile is not None:
    logger.info(f"Using AWS profile: {args.profile}")
    try:
        boto3.setup_default_session(profile_name=args.profile)
    except Exception as e:
        logger.error(
            f"Boto error {e} creating session using specified profile {args.profile}"
        )
        exit(1)

# AWS Route 53 is global, not regional, so we can ignore region for Route 53 connection.
try:
    route53 = boto3.client("route53")
except Exception as e:
    logger.error(f"Boto error {e} creating Route 53 client")
    exit(1)

# EC2 is regional, so we need to use region if specified (we use EC2 to look up instance IP addresses)
if args.region is not None:
    logger.info(f"Using AWS region: {args.region}")
    try:
        ec2 = boto3.client("ec2", region_name=args.region)
    except Exception as e:
        logger.error(
            f"Boto error {e} creating EC2 client in specified region {args.region}"
        )
        exit(1)
else:
    try:
        ec2 = boto3.client("ec2")
    except Exception as e:
        logger.error(f"Boto error {e} creating EC2 client in default region")
        exit(1)

# Validate and process the provided parameters
zone_name = args.zone
record_name = args.name
record_type = args.type
value = args.value
eip = args.eip
myip = args.myip
instanceid = args.instanceid

# only allow one of (value, eip, myip, instanceid) to be specified
numvalues = 0

if value is not None:
    numvalues += 1

if eip is not None:
    numvalues += 1
    value = get_ip_from_eip(args.eip)
    logger.debug(f"Calculated value from eip: {value}")

if myip:
    numvalues += 1
    value = get_my_ip()
    logger.debug(f"Calculated value from IP lookup: {value}")

if instanceid is not None:
    numvalues += 1
    value = get_instance_ip(args.instanceid)
    logger.debug(f"Calculated value from EC2 instance ID: {value}")

if numvalues > 1:
    raise ValueError(
        "Specify only one of value, eip, myip, or instanceid"
    )  # only one of value, eip, myip, or instanceid can be specified
    exit(1)

# figure out the record type if not explicitly specified
if record_type is None:
    if is_valid_ipv4_address(value):
        record_type = "A"
    elif is_valid_ipv6_address(value):
        record_type = "AAAA"
    elif is_valid_dns_name(value):
        record_type = "CNAME"
    logger.info(f"Inferred record type: {record_type}")

# look up zone id if zone name provided
zone_id = None
if zone_name is not None:
    if is_valid_dns_name(args.zone) is False:
        raise ValueError("Invalid zone name: {}".format(args.zone))
    zone_id = get_hosted_zone_id_from_name(args.zone)
    logger.debug(f"Matched zone name {zone_name} to zone ID {zone_id}")

# append the zone name to the record name if required
if record_name is not None and zone_name is not None:
    record_name = str(args.name) + "." + str(args.zone)
    logger.debug(f"Concatenated record name: {record_name}")

# figure out the action to take
if zone_id is None:
    action = "LISTZONES"
else:
    if record_name is None:
        action = "LIST"
    else:
        if record_type is None:
            action = "DESCRIBE"
        else:
            if value is None:
                if args.delete:
                    action = "DELETE"
                else:
                    raise ValueError("Must specify value for upserts")
            else:
                action = "UPSERT"

if action is None:
    raise ValueError(
        "Invalid parameter combination and/or values"
    )  # if we got here, there was a bug in the parameter validation code above
else:
    logger.info("Inferred action: {}".format(action))

# execute the action
match action:
    case "LISTZONES":
        logger.debug(f"Executing action: action:{action}")
        list_hosted_zones()
    case "LIST":
        logger.debug(f"Executing action: action:{action} zoneid:{zone_id}")
        list_rr(zone_id, ".")
    case "DESCRIBE":
        logger.debug(
            f"Executing action: action:{action} zoneid:{zone_id} recordname:{record_name}"
        )
        list_rr(zone_id, record_name)
    case "UPSERT":
        logger.debug(
            f"Executing action: action:{action} zoneid:{zone_id} recordname:{record_name} value:{value} ttl:{ttl}"  # type: ignore
        )
        change_rr(action, zone_id, record_type, record_name, value, args.ttl)
    case "DELETE":
        logger.debug(
            f"Executing action: action:{action} zoneid:{zone_id} recordname:{record_name} value:{value} ttl:{ttl}"  # type: ignore
        )
        current_record = get_current_record(zone_id, record_name)
        ttl = current_record["TTL"]
        value = current_record["Value"]
        logger.debug("Validated current record exists before attempting delete")
        try:
            change_rr(action, zone_id, record_type, record_name, value, args.ttl)
        except KeyError:  # trying to delete nonexistent record
            logger.error("Cannot delete nonexistent record.")
            exit(1)
    case _:
        raise ValueError(
            "Invalid parameter combination and/or values."
        )  # if we got here, there was a bug in the parameter validation code above

logger.info("Success")
