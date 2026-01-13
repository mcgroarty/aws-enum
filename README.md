# aws-enum

AWS resource enumeration tool that provides command-based access to enumerate various AWS resources across all accounts accessible via AWS SSO.

Currently supports:
- **Load Balancers**: ALBs, NLBs, GWLBs, and Classic ELBs
- **ECS**: Running ECS containers across clusters

## Quick Start

```bash
# View available commands
./aws-enum.py --help

# List all accounts and roles
./aws-enum.py accounts

# Enumerate all load balancers
./aws-enum.py loadbalancers

# Enumerate all ECS containers
./aws-enum.py ecs

# Get help for specific commands
./aws-enum.py accounts --help
./aws-enum.py loadbalancers --help
./aws-enum.py ecs --help
```

## Features

- **Automatic SSO Authentication**: Handles SSO token caching and automatically prompts for login when needed
- **Multi-Account Support**: Enumerates resources across all accounts accessible through AWS SSO
- **Optimized Performance**: Uses 4-way concurrency for account role checking to improve enumeration speed while maintaining API reliability
- **Flexible Region Scanning**: Scan any AWS regions via `--regions` flag (default: us-west-2)
- **Account Filtering**: Filter to specific accounts by name or ID with `--accounts`
- **All Load Balancer Types**: Lists ALBs, NLBs, GWLBs, and Classic ELBs
- **ECS Container Enumeration**: Lists running ECS tasks across clusters with age filtering
- **Detailed Output**: Shows resource details including names, types, and configuration
- **TLS Certificate Information**: Display certificate ARNs and domain names with `--show-certificates` and `--show-certificate-domains`
- **Filtering Options**: Filter for internet-facing load balancers only with `--internet-facing-only`
- **Debug Mode**: `--first-only` flag to stop after the first account with results

## Requirements

- Python 3.9+
- AWS CLI v2 configured with SSO
- Valid AWS SSO profile configured
- `SecurityAudit` role provisioned in target accounts (read-only access)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/secondlife/aws-enum.git
   cd aws-enum
   ```

2. Ensure AWS CLI v2 is installed and SSO is configured:
   ```bash
   aws configure sso
   ```

## Development Setup

### Pre-commit Hooks

This repository includes pre-commit hooks to ensure code quality and consistency.

**Quick setup (recommended):**
```bash
./scripts/install-hooks.sh
```

**Manual setup with pre-commit framework:**
```bash
# Install pre-commit framework
pip install pre-commit

# Install the hooks
pre-commit install

# Run on all files (optional)
pre-commit run --all-files
```

**Dependencies for full validation:**
```bash
# Python code quality
pip install flake8 black

# Markdown linting
npm install -g markdownlint-cli
```

### Running Checks Manually

```bash
# Check Python syntax
python3 -m py_compile aws-enum.py

# Run Python linting
flake8 --max-line-length=88 aws-enum.py

# Format Python code (optional)
black --line-length=88 aws-enum.py

# Lint markdown files
markdownlint --config .markdownlint.yaml README.md
```

## Usage

### Getting Started

**View available commands:**
```bash
./aws-enum.py --help
```

**Enumerate load balancers** with your default SSO profile (scans us-west-2 by default):
```bash
./aws-enum.py loadbalancers
```

### Load Balancer Command Options

**Get help for load balancer command:**
```bash
./aws-enum.py loadbalancers --help
```

**Scan specific regions** (comma-separated):
```bash
./aws-enum.py loadbalancers --regions us-east-1,us-west-2,eu-west-1
```

**Use a specific AWS SSO profile:**
```bash
AWS_PROFILE=my-sso-profile ./aws-enum.py loadbalancers
```

**Filter internet-facing load balancers:**
```bash
./aws-enum.py loadbalancers --internet-facing-only
```

**Show TLS certificates:**
```bash
./aws-enum.py loadbalancers --show-certificates
```

**Show certificate domain names:**
```bash
./aws-enum.py loadbalancers --show-certificate-domains
```

**Combined options:**
```bash
# Show internet-facing load balancers with certificate domains in us-west-2
./aws-enum.py loadbalancers --internet-facing-only --show-certificate-domains --regions us-west-2
```

**Debug mode** (stop after first account with load balancers):
```bash
./aws-enum.py loadbalancers --first-only
```

## Example Output

### Basic Output

```
SSO token valid. Enumerating accounts...

=== Production Account (123456789012) ===
  Region: us-west-2
    ALB/NLB/GWLB:
      web-app-alb                              application  internet-facing web-app-alb-123456789.us-west-2.elb.amazonaws.com
      api-nlb                                  network      internal       api-nlb-987654321.us-west-2.elb.amazonaws.com
    Classic ELB:
      legacy-elb                               classic      internet-facing legacy-elb-111222333.us-west-2.elb.amazonaws.com

=== Staging Account (987654321098) ===
  Region: us-west-2
    ALB/NLB/GWLB:
      staging-alb                              application  internet-facing staging-alb-444555666.us-west-2.elb.amazonaws.com
```

### Output with Certificate Domains

```
=== Production Account (123456789012) ===
  Region: us-west-2
    ALB/NLB/GWLB:
      web-app-alb                              application  internet-facing web-app-alb-123456789.us-west-2.elb.amazonaws.com
        Certificate: arn:aws:acm:us-west-2:123456789012:certificate/abcd-1234
          Domain: *.example.com
          Domain: example.com
      api-nlb                                  network      internet-facing api-nlb-987654321.us-west-2.elb.amazonaws.com
        Certificate: arn:aws:acm:us-west-2:123456789012:certificate/efgh-5678
          Domain: api.example.com
```

## Configuration

### Customizing Default Regions

Edit the `REGIONS` list in the script to change the default regions (currently `us-west-2`):
```python
REGIONS = ["us-west-2"]
```

Alternatively, use the `--regions` command-line option to override without editing the script:
```bash
./aws-enum.py loadbalancers --regions us-east-1,us-west-2,eu-west-1
```

### Customizing Role Name

Edit the `ROLE_NAME` variable to use a different IAM role:
```python
ROLE_NAME = "SecurityAudit"
```

## How It Works

1. **Authentication**: Checks for a valid SSO token in the AWS CLI cache. If none exists, triggers SSO login.
2. **Account Discovery**: Lists all accounts accessible via AWS SSO.
3. **Role Assumption**: For each account, assumes the `SecurityAudit` role to get temporary credentials.
4. **Enumeration**: Uses the temporary credentials to query load balancers in each specified region.
5. **Certificate Retrieval** (optional): For each load balancer, queries AWS Certificate Manager (ACM) to get certificate details and domain names.
6. **Filtering** (optional): Applies filters such as internet-facing only.
7. **Output**: Displays all load balancers with their key details.

## Command Structure

The tool uses a command-based interface. Use `./aws-enum.py --help` to see available commands.

### Available Commands

<!-- Keep commands sorted alphabetically -->
| Command | Description |
|---------|-------------|
| `accounts` | List all AWS SSO accounts and available roles |
| `ecs` | Enumerate running ECS containers |
| `loadbalancers` | Enumerate ALBs, NLBs, and Classic ELBs |
| `route53` | Enumerate Route53 hosted zones |

### Accounts Command

**List all accounts (simple view):**
```bash
./aws-enum.py accounts
```

**Show detailed role information:**
```bash
./aws-enum.py accounts --show-roles
```

**Include organization-wide account list:**
```bash
./aws-enum.py accounts --include-org
```

**Use with specific AWS profile:**
```bash
AWS_PROFILE=my-sso-profile ./aws-enum.py accounts
```

The accounts command shows:
- **Default**: Account names, IDs, and readiness status (✅/❌)
- **With `--show-roles`**: Available IAM roles in each account
- **With `--include-org`**: All organization accounts (requires Organizations permissions)
- Clear indicators for accounts ready for enumeration

### Load Balancer Command Options

| Option | Description |
|--------|-------------|
| `--first-only` | Stop after finding the first account with load balancers (useful for debugging) |
| `--internet-facing-only` | Show only internet-facing load balancers |
| `--show-certificates` | Display TLS certificate ARNs attached to load balancers |
| `--show-certificate-domains` | Display domain names for TLS certificates (implies `--show-certificates`) |
| `--accounts ACCOUNTS` | Comma-separated list of account names or IDs to check (default: all accounts) |
| `--regions REGIONS` | Comma-separated list of AWS regions to scan (default: us-west-2) |
| `-h, --help` | Show help message and exit |

### ECS Command Options

| Option | Description |
|--------|-------------|
| `--first-only` | Stop after finding the first account with ECS containers (useful for debugging) |
| `--show-tags` | Display tags for ECS tasks |
| `--min-age-days DAYS` | Only show tasks older than this many days (e.g., 7 or 0.5 for 12 hours) |
| `--accounts ACCOUNTS` | Comma-separated list of account names or IDs to check (default: all accounts) |
| `--regions REGIONS` | Comma-separated list of AWS regions to scan (default: us-west-2) |
| `-h, --help` | Show help message and exit |

## Troubleshooting

**Error: SecurityAudit role not provisioned**
- The script requires the `SecurityAudit` role (or configured role name) to be provisioned in each account
- Accounts without this role will be skipped
- The output shows available roles for skipped accounts

**Error: SSO login failed**
- Ensure AWS CLI v2 is installed: `aws --version`
- Configure SSO: `aws configure sso`
- Verify your SSO profile: `aws sso login --profile <profile-name>`

**No load balancers showing**
- Verify you have the correct permissions
- Check that load balancers exist in the specified regions
- Try `./aws-enum.py loadbalancers --first-only` flag to test on a single account
- Verify the regions with `--regions` option

**Certificate domains not showing**
- Ensure certificates are managed by AWS Certificate Manager (ACM)
- Verify you have ACM read permissions
- Certificates imported from external sources may have limited metadata

## License

MIT
