usage: r53 [-h] [--profile PROFILE] [--region REGION] [--delete]
           [--list-hosted-zones] [--zone ZONE] [--name NAME]
           [--type {A,AAAA,CAA,CNAME,MX,NAPTR,SPF,SRV,TXT}] [--ttl TTL]
           [--value VALUE] [--eip EIP] [--myip] [--instanceid INSTANCEID]

Manage resource records in AWS Route 53

optional arguments:
  -h, --help            show this help message and exit
  --profile PROFILE     Use a specific named profile in AWS configuration
  --region REGION       target AWS API calls against a specific region where
                        applicable
  --delete              delete a resource record from a zone
  --list-hosted-zones   list all hosted zones
  --zone ZONE           DNS name of target zone
  --name NAME           name of resource record
  --type {A,AAAA,CAA,CNAME,MX,NAPTR,SPF,SRV,TXT}
                        resource record type
  --ttl TTL             TTL (in seconds)
  --value VALUE         value to set in resource record
  --eip EIP             EIP allocation ID; sets value to the EIP address. Type
                        and value parameters are ignored if EIP is specified.
  --myip                sets value to the calling computers public IP address.
                        Type and value parameters are ignored if myip is
                        specified.  Local IP is looked up at https://checkip.amazonaws.com
  --instanceid INSTANCEID
                        EC2 instance ID; sets value to the public IP address
                        of the instance. Type and value parameters are ignored
                        if instanceid is specified.
                        
This script does simple management of Route 53 zones, using the AWS API.  You must have the AWS CLI
properly configured with a credentials file containing valid AWS keys.  The script supports use of
profiles if you have multiple key sets configured properly.

The script supports use of regional endpoints for EC2.

How to configure AWS:
You could install the AWS CLI and use "aws configure":
https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
or do it manually:
Credentials & configuration: https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html
Profiles: https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html

The following AWS permissions are required; set them using IAM policy on the IAM user you're using.
ec2:DescribeInstances
route53:ListHostedZones
route53:ListResourceRecordSets
route53:ChangeResourceRecordSets

The script has only been tested using Python 3.6 and 3.7.

You must install argparse and boto3 in the python environment where you're going to run the script:
pip install argparse
pip install boto3

The script tries to infer as much information as possible:
- If no zone is specified, the script attempts to list hosted zones.
- If only a zone and a record name are specified, the script attempts to look up and display matching records.
- If a new value is provided for the record itself or for the TTL, the script attempts to upsert (add or update) the record.
- Deletes explicitly require the --delete option.
- Type is optional if the type can be cleanly inferred from the value (e.g. A, AAAA or CNAME).

r53 --help                                              # the above text
r53                                                     # list hosted zones
r53 --zone example.com --name test                      # display all records with name test in zone example.com
r53 --zone example.com --name test --type A --delete    # type is required for delete
r53 --zone example.com --name test --myip               # create/update an A record named test using your ip (i.e. dynamic DNS)
r53 --zone example.com --name test --eip <eip-id>       # create/update an A record for an EIP
r53 --zone example.com --name test --instanceid i-123   # create/update an A record for the public IP addr of an instance
r53 --zone example.com --name test --value 1.2.3.4      # create/update an A record (--type A is optional as IPv4 implies A)
r53 --zone example.com --name test --value ::1          # create/update an AAAA record (--type AAAA is optional as IPv6 implies AAAA)
r53 --zone example.com --name test --value foo.bar.com  # create/update a CNAME record (--type CNAME is optional as hostname implies)
r53 --profile work ...                                  # use the keys and configuration from the work profile in .aws/credentials
r53 --region us-east-1                                  # override the region specified in .aws configuration (where is your instance?)

The script doesn't support aliases or weighting because I don't understand or use them.  It doesn't support management of zones because this is too rare a task for me to automate.  It doesn't support all record types that Route53 supports because I don't want to accidentally mess up my zone records.  It doesn't do a lot of error checking, expecting boto to throw useful exceptions.

Troubleshooting:
botocore InvalidClientTokenId  - this means that your credentials are wrong or missing.  Set up new a new key pair with IAM.

The command line parser is really buggy and could use a cleanup.  If you're interested, send a pull request.
