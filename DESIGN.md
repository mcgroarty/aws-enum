# Design & Architecture

This document describes the internal design and implementation details of aws-enum.

## How It Works

1. **Authentication**: Checks for a valid SSO token in the AWS CLI cache. If none exists, triggers SSO login via `aws sso login`.
2. **Account Discovery**: Lists all accounts accessible via AWS SSO using boto3.
3. **Role Assumption**: For each account, assumes the `SecurityAudit` role to get temporary credentials.
4. **Enumeration**: Uses boto3 clients with the temporary credentials to query resources in each specified region.
5. **Certificate Retrieval** (optional): For load balancers, queries AWS Certificate Manager (ACM) to get certificate details and domain names.
6. **Filtering** (optional): Applies filters such as internet-facing only.
7. **Output**: Displays all resources with their key details.

## Performance Optimizations

- **Concurrent Role Checking**: Uses 10-way concurrency with ThreadPoolExecutor for account role checking
- **Thread-Local Clients**: boto3 SSO clients are cached per-thread to avoid contention
- **Retry Logic**: boto3 adaptive retry mode with 3 max attempts
- **Token Caching**: Reuses valid SSO tokens from AWS CLI cache

## Module Structure

```
aws_enum/
├── __init__.py          # Package exports main()
├── __main__.py          # Entry point for python -m aws_enum
├── auth.py              # SSO token handling, login flow
├── client.py            # boto3 client management, thread-local caching
├── accounts.py          # Account/role enumeration
├── loadbalancers.py     # ELB/ALBv2 enumeration
├── ecs.py               # ECS container enumeration
├── iam.py               # IAM summary and user inventory
├── route53.py           # Route53 DNS enumeration
└── cli.py               # Argparse setup, main()
```

## Configuration Variables

Located in `aws_enum/cli.py` and `aws_enum/accounts.py`:

```python
ROLE_NAME = "SecurityAudit"  # IAM role to assume in each account
REGIONS = ["us-west-2"]      # Default regions to scan
```

Both can be overridden via command-line options (`--regions`) or by editing the module.

## AWS API Calls (via boto3)

### SSO Operations

- `sso.list_accounts()` - Discover accessible accounts
- `sso.list_account_roles()` - Check available roles per account
- `sso.get_role_credentials()` - Get temporary credentials

### Resource Enumeration

- `elbv2.describe_load_balancers()` - ALB/NLB/GWLB
- `elb.describe_load_balancers()` - Classic ELB
- `elbv2.describe_listeners()` - TLS certificates on ALB/NLB
- `acm.describe_certificate()` - Certificate domain details
- `ecs.list_clusters()` / `describe_tasks()` - ECS containers
- `route53.list_hosted_zones()` / `list_resource_record_sets()` - DNS zones
- `iam.get_account_summary()` - High-level IAM object counts
- `iam.generate_credential_report()` / `get_credential_report()` - IAM credential activity
- `iam.list_users()` / `list_groups_for_user()` - IAM user inventory
- `iam.list_roles()` / `get_role()` - IAM role trust inventory and last-used data

### Organization Operations (optional)

- `organizations.list_accounts()` - List all org accounts
- `organizations.describe_organization()` - Identify master account

## Development Setup

```bash
pip install pre-commit
pre-commit install
```

Hooks run automatically on commit. To run manually:

```bash
pre-commit run --all-files
```

## External Detection (Route53)

The Route53 command can identify external (non-AWS) DNS targets using pattern matching:

```python
AWS_DNS_PATTERNS = [
    r'\.elb\.amazonaws\.com$',
    r'\.cloudfront\.net$',
    r'\.s3\.amazonaws\.com$',
    r'\.rds\.amazonaws\.com$',
    r'\.execute-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$',
    # ... etc
]
```

Any CNAME not matching these patterns is flagged as 🔶 External.
