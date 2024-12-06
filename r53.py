#!/usr/bin/env python3
import argparse
import boto3
import urllib.request as request
import socket
import re


def get_instance_ip(instance_id):
    response = ec2.describe_instances(InstanceIds=[instance_id])
    for r in response["Reservations"]:
        for i in r["Instances"]:
            return i["PublicIpAddress"]


def get_ip_from_eip(eip):
    response = ec2.describe_addresses(AllocationIds=[eip])
    for a in response["Addresses"]:
        return a["PublicIp"]


def get_my_ip():
    with request.urlopen("https://checkip.amazonaws.com") as f:
        return f.read().decode("utf-8").strip()


# https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return (
            address.count(".") == 3
        )  # ensure that the address was complete and not padded with 0's by the socket library
    except socket.error:  # not a valid address
        return False
    except TypeError:
        return False
    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    except TypeError:
        return False
    return True


# https://stackoverflow.com/questions/2532053/validate-a-hostname-string
def is_valid_dns_name(p_dns_name):
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
    print("Validated DNS name: {}", validated_dns_name)
    return validated_dns_name


def is_valid_hostname(hostname):
    # noinspection PyPep8
    allowed = re.compile(
        r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\
(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$",
        re.IGNORECASE,
    )
    return allowed.match(hostname)


def get_hosted_zone_id_from_name(p_domain_name):
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
print(args)  # for debugging

if args.profile is not None:
    boto3.setup_default_session(profile_name=args.profile)

# AWS Route 53 is global, not regional, so we can ignore region for Route 53 connection.
route53 = boto3.client("route53")

if args.region is not None:
    ec2 = boto3.client("ec2", region_name=args.region)
else:
    ec2 = boto3.client("ec2")

# we're going to infer the desired action from the parameters provided
action = "ERROR"  # assume that the parameter combination is erroneous until we find a valid combination

if args.zone is None:
    action = "LISTZONES"  # we need a zone name for almost everything.  No zone name -> list zones
elif (
    args.name is None
):  # we need a record name for any record manipulation.  No record name -> list records in zone
    action = "LIST"

# figure out the action to set
value = args.value

# figure out the action if no value is specified
if (
    value is None and action == "ERROR"
):  # we don't know the action yet, so you must want to manipulate a record
    # but if you didn't give us a value, then we have to figure out what you
    # want to do
    if (
        args.myip
    ):  # if you used -myip, then you want to upsert your internet IP as the record's value
        value = get_my_ip()
        action = "UPSERT"
    elif (
        args.eip is not None
    ):  # if you specified an EIP, then you want to upsert the EIP as the record's value
        value = get_ip_from_eip(args.eip)
        action = "UPSERT"
    elif (
        args.instanceid is not None
    ):  # if you specified an instance ID, then you want to upsert the instance's public IP as the record's value
        value = get_instance_ip(args.instanceid)
        action = "UPSERT"
    elif args.delete:
        raise ValueError("Delete requires zone name, record name, and record type.")
    else:  # you gave a record zone and name but no value, so you want to describe the record
        action = "DESCRIBE"

# figure out the record type if implied
record_type = args.type
if record_type is None:
    if is_valid_ipv4_address(value):
        record_type = "A"
    elif is_valid_ipv6_address(value):
        record_type = "AAAA"
    elif is_valid_dns_name(value):
        record_type = "CNAME"
    elif action != "LIST" and action != "LISTZONES" and action != "DESCRIBE":
        raise ValueError("Unable to determine record type")

# if it's a delete, verify value and type are present
if args.delete:
    if value is None or record_type is None:
        raise ValueError("Delete requires zone name, record name, and record type.")
    action = "DELETE"

zone_id = ""
record_id = ""

# for actions requiring a zone, verify that the provided zone name is valid and then get the zone id
if action == "LIST" or action == "DELETE" or action == "UPSERT" or action == "DESCRIBE":
    if is_valid_dns_name(args.zone) is False:
        raise ValueError("Invalid zone name: {}".format(args.zone))
    zone_id = get_hosted_zone_id_from_name(args.zone)

record_name = ""

# append the zone name to the record name if required
if action == "DELETE" or action == "UPSERT" or action == "DESCRIBE":
    record_name = str(args.name) + "." + str(args.zone)

ttl = args.ttl

# for Route 53 record deletes, you have to specify everything about the record to be deleted, so we look it all up in preparation
if action == "DELETE":
    try:
        current_record = get_current_record(zone_id, record_name)
        ttl = current_record["TTL"]
        value = current_record["Value"]
    except KeyError:
        print("Record does not exist.")
        exit(1)

# do the thing with the stuff
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
    )  # we should never get here

print("Success")
