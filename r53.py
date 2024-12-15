#!/usr/bin/env python3
import argparse
import boto3
import urllib.request as request
import socket
import re


def get_instance_ip(instance_id):
    """
    Given an instance id, returns the public IP address of that instance.
    """
    response = ec2.describe_instances(InstanceIds=[instance_id])
    for r in response["Reservations"]:
        for i in r["Instances"]:
            return i["PublicIpAddress"]


def get_ip_from_eip(eip):
    """
    Given an Elastic IP Allocation Id, returns the public IP address of that Elastic IP address.
    """
    response = ec2.describe_addresses(AllocationIds=[eip])
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
        re_ipv4 = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        is_ipv4 = (address == re_ipv4.match(address))
        return (
            is_ipv4
            #address.count(".") == 3 # the old way was just counting the dots
        )
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
            re.IGNORECASE
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


def list_hosted_zones():
    """
    List all hosted zones in Route 53.

    This function iterates over all hosted zones in Route 53 and prints out each
    zone's ID and name.

    :return: None
    """
    paginator = route53.get_paginator("list_hosted_zones")
    response_iterator = paginator.paginate()
    for response in response_iterator:
        zones = response["HostedZones"]
        for zone in zones:
            l_zone_id = (zone["Id"].split("/")[-1:])[0]
            l_zone_name = zone["Name"].rstrip(".")
            print(l_zone_id, l_zone_name)
    return


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
    return


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
    return response


parser = argparse.ArgumentParser(
    prog="r53", description="Manage resource records in AWS Route 53"
)

parser.add_argument(
    "--profile",
    action="store",
    help="Uses a specific named profile in AWS configuration.  Otherwise uses the default profile.",
)
parser.add_argument(
    "--region",
    action="store",
    help="Targets AWS API calls against the specified region; default region for the account or the profile is used otherwise",
)
parser.add_argument(
    "--delete",
    action="store_true",
    help="Deletes a resource record from a zone.",
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
print("Arguments: " + str(args))  # for debugging

if args.profile is not None:
    # print("Using profile: " + args.profile)
    boto3.setup_default_session(profile_name=args.profile)

# AWS Route 53 is global, not regional, so we can ignore region for Route 53 connection.
route53 = boto3.client("route53")

# However EC2 is regional, so we need to use region if specified
if args.region is not None:
    # print("Using region: " + args.region)
    ec2 = boto3.client("ec2", region_name=args.region)
else:
    ec2 = boto3.client("ec2")

# we're going to infer the desired action from the parameters provided
action = "ERROR"  # assume that the parameter combination is erroneous until we find a valid combination

if args.delete:
    action = "DELETE"

if args.zone is None:
    action = "LISTZONES"  # we need a zone name for almost everything.  No zone name -> list zones
    if args.name is None:  # we need a record name for any record manipulation.  No record name -> list records in zone
        action = "LIST"
elif args.name is None:
        raise ValueError("You must specify both a zone and a record name for record operations")

value = args.value

# figure out the action if no value is specified
if (action != "LISTZONES" and action != "LIST" and action != "DELETE"):
    if args.value is None:
        if args.myip:  # if you used -myip, then you want to upsert your internet IP as the record's value
            value = get_my_ip()
            print("Calculated value: {}".format(value))
            action = "UPSERT"
        elif args.eip is not None:  # if you specified an EIP, then you want to upsert the EIP as the record's value
            value = get_ip_from_eip(args.eip)
            print("Calculated value: {}".format(value))
            action = "UPSERT"
        elif args.instanceid is not None:  # if you specified an instance ID, then you want to upsert the instance's public IP as the record's value
            value = get_instance_ip(args.instanceid)
            print("Calculated value: {}".format(value))
            action = "UPSERT"
        else:  # you gave a record zone and name but no value, so you want to describe the record
            action = "DESCRIBE"
    else:
        action = "UPSERT"
    print("Inferred action: {}".format(action))

record_type = args.type

# figure out the record type if not explicitly specified
if record_type is None:
    if is_valid_ipv4_address(value):
        record_type = "A"
    elif is_valid_ipv6_address(value):
        record_type = "AAAA"
    elif is_valid_dns_name(value):
        record_type = "CNAME"
    elif action != "LIST" and action != "LISTZONES" and action != "DESCRIBE":
        raise ValueError("Unable to determine record type")
    print("Inferred record type: {}".format(record_type))

zone_id = ""

# for actions requiring a zone, verify that the provided zone name is valid and then get the zone id
if action == "LIST" or action == "DELETE" or action == "UPSERT" or action == "DESCRIBE":
    if is_valid_dns_name(args.zone) is False:
        raise ValueError("Invalid zone name: {}".format(args.zone))
    zone_id = get_hosted_zone_id_from_name(args.zone)
    print("Zone ID: {}".format(zone_id))

record_name = ""

# append the zone name to the record name if required
if action == "DELETE" or action == "UPSERT" or action == "DESCRIBE":
    record_name = str(args.name) + "." + str(args.zone)
    print("Record name: {}".format(record_name))

ttl = args.ttl

# for Route 53 record deletes, you have to specify everything about the record to be deleted, so we look it all up in preparation
if action == "DELETE":
    if record_type is None:
        raise ValueError("Must specify record type for deletes")
    try:
        current_record = get_current_record(zone_id, record_name)
        ttl = current_record["TTL"]
        value = current_record["Value"]
        print("Validated current record exists before delete")
    except KeyError: # trying to delete nonexistent record
        print("Cannot delete nonexistent record.")
        exit(1)

# we've verified that we have a valid action and all necessary parameters, so let's do it
if action == "LISTZONES":
    print("Action: {}".format(action))
    list_hosted_zones()
elif action == "LIST":
    print("Action: {}, zone: {}".format(action, zone_id))
    list_rr(zone_id, ".")
elif action == "DESCRIBE":
    print("Action: {}, zone: {}, name: {}".format(action, zone_id, record_name))
    list_rr(zone_id, record_name)
elif action == "UPSERT" or action == "DELETE":
    print(
        "Action: {}, zone: {}, type: {}, name: {}, value: {}, ttl: {}".format(
            action, zone_id, record_type, record_name, value, ttl
        )
    )
    change_rr(action, zone_id, record_type, record_name, value, args.ttl)
else:
    raise ValueError(
        "Invalid parameter combination and/or values."
    )  # if we got here, there was a bug in the parameter validation code above

print("Success")
