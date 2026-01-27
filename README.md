# aws-enum

AWS resource enumeration tool for multi-account environments using AWS SSO.

## Quick Start

```bash
# View available commands
./aws-enum.py --help

# List all accounts and roles
./aws-enum.py accounts

# Enumerate load balancers
./aws-enum.py loadbalancers

# Enumerate ECS containers
./aws-enum.py ecs

# Enumerate Route53 hosted zones
./aws-enum.py route53
```

## Requirements

- Python 3.9+
- AWS CLI v2 configured with SSO
- `SecurityAudit` role provisioned in target accounts

## Installation

```bash
git clone https://github.com/mcgroarty/aws-enum.git
cd aws-enum
aws configure sso  # if not already configured
```

## Commands

| Command | Description |
|---------|-------------|
| `accounts` | List all AWS SSO accounts and available roles |
| `loadbalancers` | Enumerate ALBs, NLBs, GWLBs, and Classic ELBs |
| `ecs` | Enumerate running ECS containers |
| `route53` | Enumerate Route53 hosted zones and DNS records |

Use `./aws-enum.py <command> --help` for command-specific options.

## Common Options

Most commands support these options:

| Option | Description |
|--------|-------------|
| `--accounts` | Filter to specific account names or IDs |
| `--regions` | Comma-separated regions to scan (default: us-west-2) |
| `--first-only` | Stop after first account with results (debugging) |

## Examples

**Use a specific AWS SSO profile:**

```bash
AWS_PROFILE=my-sso-profile ./aws-enum.py loadbalancers
```

**Scan multiple regions:**

```bash
./aws-enum.py loadbalancers --regions us-east-1,us-west-2,eu-west-1
```

**Filter to specific accounts:**

```bash
./aws-enum.py ecs --accounts "Production,Staging"
```

**Show internet-facing load balancers with TLS certificate domains:**

```bash
./aws-enum.py loadbalancers --internet-facing-only --show-certificate-domains
```

**Show Route53 records pointing to external (non-AWS) targets:**

```bash
./aws-enum.py route53 --show-records --external-only
```

**Export Route53 records to CSV:**

```bash
./aws-enum.py route53 --csv records.csv
```

## Example Output

```text
SSO token valid. Enumerating accounts...

=== Production Account (123456789012) ===
  Region: us-west-2
    ALB/NLB/GWLB:
      web-app-alb                application  internet-facing  web-app-alb-123.elb.amazonaws.com
      api-nlb                    network      internal         api-nlb-456.elb.amazonaws.com

=== Staging Account (987654321098) ===
  Region: us-west-2
    ALB/NLB/GWLB:
      staging-alb                application  internet-facing  staging-alb-789.elb.amazonaws.com
```

## Troubleshooting

**SSO login failed**

```bash
aws --version        # Ensure AWS CLI v2
aws configure sso    # Configure SSO
aws sso login        # Test login
```

**SecurityAudit role not provisioned**

- Accounts without the `SecurityAudit` role are skipped
- Run `./aws-enum.py accounts --show-roles` to see available roles

**No results showing**

- Verify resources exist in the scanned regions
- Use `--first-only` to test on a single account
- Check the `--regions` setting

## Contributing

See [DESIGN.md](DESIGN.md) for architecture and development setup.

## License

Apache License 2.0
