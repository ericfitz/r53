# R53.py - Command Line Route 53 interface with Dynamic DNS support

This Python 3.10+ script does simple management of Route 53 zones and records using the AWS API. You must have the AWS CLI properly configured with a credentials file containing valid AWS keys. The script supports use of profiles if you have multiple key sets configured properly.

The script trivially does dynamic DNS using the "--myip" parameter to look up its own public IP and use it to update an A record.

The script can also set an A record to an EC2 instance's public IP address, even if the instance is in a different region.

## COMMAND LINE HELP

```
usage: r53 [-h] [--profile PROFILE] [--region REGION] [--delete] [--zone ZONE]
           [--name NAME]
           [--type {A,AAAA,CAA,CNAME,MX,NAPTR,NS,PTR,SOA,SPF,SRV,TXT}]
           [--ttl TTL] [--value VALUE] [--eip EIP] [--myip]
           [--instanceid INSTANCEID]

Manage resource records in AWS Route 53

options:
  -h, --help            show this help message and exit
  --profile PROFILE     Use the specified AWS configuration profile instead of
                        the default profile.
  --region REGION       Targets AWS API calls against the specified region
                        instead of the default region in AWS configuration.
  --delete              Delete a resource record from a zone.
  --zone ZONE           DNS name of target zone
  --name NAME           name of resource record
  --type {A,AAAA,CAA,CNAME,MX,NAPTR,NS,PTR,SOA,SPF,SRV,TXT}
                        Specifies the DNS resource record type
  --ttl TTL             TTL (in seconds, 0-2147483647)
  --value VALUE         Specifies the value to set in the resource record
  --eip EIP             Sets value to the IP address associated with the
                        specified EIP. Type and value parameters are ignored
                        if EIP is specified.
  --myip                Uses the calling computer's public IP address. Type
                        and value parameters are ignored if --myip is
                        specified. Local IP is looked up at
                        https://checkip.amazonaws.com
  --instanceid INSTANCEID
                        Sets value to the public IP address of the specified
                        EC2 instance. Type and value parameters are ignored if
                        instance ID is specified.
```

To list hosted zones, run the script with no `--zone` argument.

## SETUP

1. Install the AWS command line interface (CLI)

   - https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html

2. Configure the AWS CLI

   You could install the AWS CLI and use "aws configure":

   - https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html

   or do it manually:

   - Credentials & configuration: https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html
   - Profiles: https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html

3. Permissions

   The following AWS permissions are required; set them using IAM policy on the IAM user or role you're using.

   - ec2:DescribeInstances (required for `--instanceid`)
   - ec2:DescribeAddresses (required for `--eip`)
   - route53:ListHostedZones
   - route53:ListResourceRecordSets
   - route53:ChangeResourceRecordSets

4. Install uv (recommended) or configure your Python environment

   **Option A: Using uv (recommended)**

   Install uv if you haven't already:
   ```
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

   Or on macOS with Homebrew:
   ```
   brew install uv
   ```

   No additional setup needed! uv will automatically manage dependencies when you run the script.

   **Option B: Manual Python environment**

   Install boto3 in your Python 3.10+ environment:
   ```
   pip install boto3
   ```

## USING THE SCRIPT

The script tries to infer as much information as possible:

- If no zone is specified, the script attempts to list hosted zones.
- If only a zone and a record name are specified, the script attempts to look up and display matching records.
- If a new value is provided for the record itself or for the TTL, the script attempts to upsert (add or
  update) the record.
- Deletes explicitly require the --delete option.
- Type is optional if the type can be cleanly inferred from the value and the value is correctly formatted (e.g. A, AAAA or CNAME).

## EXAMPLES

**Using uv (recommended):**
```bash
uv run r53.py --help                                              # the above text
uv run r53.py                                                     # list hosted zones
uv run r53.py --zone example.com --name test                      # display all records with name test in zone example.com
uv run r53.py --zone example.com --name test --type A --delete    # type is required for delete
uv run r53.py --zone example.com --name test --myip               # create/update an A record named test using your ip
                                                                    (i.e. dynamic DNS)
uv run r53.py --zone example.com --name test --eip <eip-id>       # create/update an A record for an EIP
uv run r53.py --zone example.com --name test --instanceid i-123   # create/update an A record for the public IP addr of
                                                                    an instance
uv run r53.py --zone example.com --name test --value 1.2.3.4      # create/update an A record (--type A is optional as
                                                                    IPv4 implies A)
uv run r53.py --zone example.com --name test --value ::1          # create/update an AAAA record (--type AAAA is optional
                                                                    as IPv6 implies AAAA)
uv run r53.py --zone example.com --name test --value foo.bar.com  # create/update a CNAME record (--type CNAME is optional
                                                                    as hostname implies CNAME)
uv run r53.py --profile profilename ...                           # use the keys and configuration from the profilename
                                                                    profile in ~/.aws/credentials
uv run r53.py --region us-east-1 ...                              # override the region specified in .aws configuration
                                                                    (where is your instance?)
```

**Or using python directly (if you installed dependencies manually):**
```bash
python r53.py --help
python r53.py --zone example.com --name test --myip
# ... etc
```

## NOTES

The script doesn't support aliases, weighted routing, or routing policies. Alias records
can be listed but cannot be created, modified, or deleted. Multi-value records can be
viewed but cannot be deleted. It doesn't support management of zones. It doesn't support
all record types that Route53 supports.

## TROUBLESHOOTING

botocore InvalidClientTokenId - this means that your credentials are wrong or missing. Set up new a new key pair with IAM.

On any error, the script logs a message and exits with code `1`. On success, it exits with code `0`. This makes it safe to use in shell pipelines (`&&`, `||`) and cron (where a non-zero exit can trigger mail/alerts).

## DYNAMIC DNS

To implement dynamic DNS without subscribing to one of the public DDNS providers:

1. Register a domain (e.g. "mydomain.com") and host it with Route 53

2. Configure this tool as described above in "SETUP"

3. Choose a record name to use for DDNS, e.g. "home" ("home.mydomain.com").

4. Configure the tool to run regularly to create and update that A record with your IP address. Run this regularly from a computer behind that IP address, e.g. on a home server using a CRON job.

```bash
uv run r53.py --zone example.com --name home --myip
```

Or add this to your crontab to update every 5 minutes:
```bash
*/5 * * * * cd /path/to/r53 && uv run r53.py --zone example.com --name home --myip >> /var/log/ddns.log 2>&1
```
