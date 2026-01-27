# Design & Architecture

This document describes the internal design and implementation details of aws-enum.

## How It Works

1. **Authentication**: Checks for a valid SSO token in the AWS CLI cache. If none exists, triggers SSO login.
2. **Account Discovery**: Lists all accounts accessible via AWS SSO.
3. **Role Assumption**: For each account, assumes the `SecurityAudit` role to get temporary credentials.
4. **Enumeration**: Uses the temporary credentials to query resources in each specified region.
5. **Certificate Retrieval** (optional): For load balancers, queries AWS Certificate Manager (ACM) to get certificate details and domain names.
6. **Filtering** (optional): Applies filters such as internet-facing only.
7. **Output**: Displays all resources with their key details.

## Performance Optimizations

- **Concurrent Role Checking**: Uses 10-way concurrency for account role checking to improve enumeration speed while maintaining API reliability
- **Retry Logic**: Exponential backoff on API failures when fetching account roles
- **Token Caching**: Reuses valid SSO tokens from AWS CLI cache

## Configuration Variables

The script has two main configuration variables at the top:

```python
ROLE_NAME = "SecurityAudit"  # IAM role to assume in each account
REGIONS = ["us-west-2"]      # Default regions to scan
```

Both can be overridden via command-line options (`--regions`) or by editing the script.

## AWS API Calls

### SSO Operations

- `aws sso list-accounts` - Discover accessible accounts
- `aws sso list-account-roles` - Check available roles per account
- `aws sso get-role-credentials` - Get temporary credentials

### Resource Enumeration

- `aws elbv2 describe-load-balancers` - ALB/NLB/GWLB
- `aws elb describe-load-balancers` - Classic ELB
- `aws elbv2 describe-listeners` - TLS certificates on ALB/NLB
- `aws acm describe-certificate` - Certificate domain details
- `aws ecs list-clusters` / `describe-tasks` - ECS containers
- `aws route53 list-hosted-zones` / `list-resource-record-sets` - DNS zones

### Organization Operations (optional)

- `aws organizations list-accounts` - List all org accounts
- `aws organizations describe-organization` - Identify master account

## Code Structure

The script is organized into sections:

1. **Utility Functions**: `format_age()`, `get_task_age_days()`
2. **SSO Functions**: Token caching, login, credential retrieval
3. **AWS CLI Wrapper**: `run_aws_cli()`, `run_sso_command()`
4. **Resource Functions**: Per-service enumeration (ELB, ECS, Route53)
5. **Command Handlers**: `enumerate_accounts()`, `enumerate_loadbalancers()`, etc.
6. **Main/CLI**: Argument parsing and command routing

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
