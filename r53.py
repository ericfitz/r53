#!/usr/bin/env python3
import argparse
import boto3
import urllib.request as request
import socket
import re

def get_instance_ip(instanceid):
    response = ec2.describe_instances(InstanceIds=[instanceid])
    for r in response['Reservations']:
        for i in r['Instances']:
            return i['PublicIpAddress']

def get_ip_from_eip(eip):
    response = ec2.describe_addresses(AllocationIds=[eip])
    for a in response['Addresses']:
        return a['PublicIp']

def get_my_ip():
    with request.urlopen("https://checkip.amazonaws.com") as f:
        return f.read().decode('utf-8').strip()

# https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3 # ensure that the address was complete and not padded with 0's by the socket library
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

# https://stackoverflow.com/questions/2532053/validate-a-hostname-string
def is_valid_dnsname(dnsname):
    if len(dnsname) > 255:
        return False
    if dnsname[-1] == ".":
        dnsname = dnsname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in dnsname.split("."))

def is_valid_hostname(hostname):
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return allowed.match(hostname)

def get_hosted_zone_id_from_name(domainname):
    paginator = route53.get_paginator('list_hosted_zones')
    response_iterator = paginator.paginate()
    for response in response_iterator:
        zones = response['HostedZones']
        for zone in zones:
            zoneid = (zone['Id'].split("/")[-1:])[0] # split by / into a list of strings, get list of last string only, convert list to string
            zonename = zone['Name'].rstrip(".") # remove trailing .
            if zonename == domainname:
                return zoneid
    return None

def list_hosted_zones():
    paginator = route53.get_paginator('list_hosted_zones')
    response_iterator = paginator.paginate()
    for response in response_iterator:
        zones = response['HostedZones']
        for zone in zones:
            zoneid = (zone['Id'].split("/")[-1:])[0]
            zonename = zone['Name'].rstrip(".")
            print(zoneid, zonename)
    return

def get_current_record(zone, type, name):
    dict = {}
    paginator = route53.get_paginator('list_resource_record_sets')
    response_iterator = paginator.paginate(HostedZoneId=zone, StartRecordName=name)
    for response in response_iterator:
        rrsets = response['ResourceRecordSets']
        for rrset in rrsets:
            rrset_name = rrset['Name'].rstrip(".")
            if name == rrset_name:
                rrs = rrset['ResourceRecords']
                for rr in rrs:
                    dict['Name'] = rrset_name
                    dict['Type'] = rrset['Type']
                    dict['TTL'] = rrset['TTL']
                    dict['Value'] = rr['Value']
    return dict

def list_rr(zone, name):
    paginator = route53.get_paginator('list_resource_record_sets')
    response_iterator = paginator.paginate(HostedZoneId=zone, StartRecordName=name)
    for response in response_iterator:
        rrsets = response['ResourceRecordSets']
        for rrset in rrsets:
            rrset_name = rrset['Name'].rstrip(".")
            if name == rrset_name:
                rrs = rrset['ResourceRecords']
                for rr in rrs:
                    print('Name: {}, Type: {}, TTL: {}, Value: {}'.format(rrset_name, rrset['Type'], rrset['TTL'], rr['Value']))
    return

def change_rr(action, zone, type, name, value, ttl):
    response = route53.change_resource_record_sets(
        HostedZoneId=zone,
        ChangeBatch={
            'Comment': 'r53.py',
            'Changes': [
                {
                    'Action': action,
                    'ResourceRecordSet': {
                        'Name': name,
                        'Type': type,
                        'TTL': ttl,
                        'ResourceRecords': [
                            {
                                'Value': value
                            },
                        ]
                    }
                },
            ]
        }
    )
    return

parser = argparse.ArgumentParser(prog='r53', description='Manage resource records in AWS Route 53')

parser.add_argument('--profile', action='store', help='Use a specific named profile in AWS configuration')
parser.add_argument('--region', action='store', help='target AWS API calls against a specific region where applicable')
parser.add_argument('--delete', action='store_true', help='delete a resource record from a zone (default operation is upsert if a value or TTL is specified, and describe otherwise)')
# default operation is list. If a value is specified, operation is upsert.  Delete must be explicit.
parser.add_argument('--zone', action='store', help='DNS name of target zone')
parser.add_argument('--name', action='store', help='name of resource record')
parser.add_argument('--type', action='store', help='resource record type', choices=['A','AAAA','CAA','CNAME','MX','NAPTR','SPF','SRV','TXT'])
# default type is A if value matches an IPv4 regex, AAAA if value matches an IPv6 regex, and CNAME otherwise
parser.add_argument('--ttl', action='store', type=int, default=300, help='TTL (in seconds)')
parser.add_argument('--value', action='store', help='value to set in resource record')
parser.add_argument('--eip', action='store', help='EIP allocation ID; sets value to the EIP address. Type and value parameters are ignored if EIP is specified.')
parser.add_argument('--myip', action='store_true', help='sets value to the calling computer''s public IP address. Type and value parameters are ignored if EIP is specified.')
parser.add_argument('--instanceid', action='store', help='EC2 instance ID; sets value to the public IP address of the instance. Type and value parameters are ignored if instance is specified.')

args = parser.parse_args()

if args.profile != None:
    boto3.setup_default_session(profile_name=args.profile)

# AWS Route 53 is global, not regional, so we can ignore region
route53 = boto3.client('route53')

if args.region != None:
    ec2 = boto3.client('ec2', region_name=args.region)
else:
    ec2 = boto3.client('ec2')

# no validation needed for zone - let Route 53 raise the exception

# no validation needed for name - let Route 53 raise the exception

# figure out the value to set
value = args.value
if value == None:
    if args.myip == True:
        value = get_my_ip()
    elif args.eip != None:
        value = get_ip_from_eip(args.eip)
    elif args.instanceid != None:
        value = get_instance_ip(args.instanceid)

# figure out the action
action = 'LIST'
if value != None:
    action = 'UPSERT'
elif args.delete == True:
    action = 'DELETE'
elif args.zone == None:
    action = 'LISTZONES'

# figure out the record type if implied
type = args.type
if type == None and value != None:
    if is_valid_ipv4_address(value):
        type = 'A'
    elif is_valid_ipv6_address(value):
        type = 'AAAA'
    elif is_valid_dnsname(value):
        type = 'CNAME'
    elif action != 'list':
        raise ValueError('Unable to determine record type')

zoneid = get_hosted_zone_id_from_name(args.zone)
record_name = args.name + "." + args.zone
ttl = args.ttl

if action == 'DELETE':
    current_record = get_current_record(zoneid, type, record_name)
    ttl = current_record['TTL']
    value = current_record['Value']

# do the thing with the stuff
if action == 'LIST':
    print('Action: {}, zone: {}, name: {}'.format(action, zoneid, record_name))
    list_rr(zoneid, record_name)
elif action == 'LISTZONES':
    print('Action: {}'.format(action))
    list_hosted_zones()
elif action == 'UPSERT' or action == 'DELETE':
    print('Action: {}, zone: {}, type: {}, name: {}, value: {}, ttl: {}'.format(action, zoneid, type, record_name, value, ttl))
    change_rr(action, zoneid, type, record_name, value, args.ttl)

print('Success')