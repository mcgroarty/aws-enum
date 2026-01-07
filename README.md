# aws-enumerate-elbs

Enumerate Application Load Balancers (ALBs), Network Load Balancers (NLBs), Gateway Load Balancers (GWLBs), and Classic ELBs across all AWS accounts accessible via AWS SSO.

## Features

- **Automatic SSO Authentication**: Handles SSO token caching and automatically prompts for login when needed
- **Multi-Account Support**: Enumerates load balancers across all accounts accessible through AWS SSO
- **Flexible Region Scanning**: Scan any AWS regions via `--regions` flag (default: us-west-2)
- **All Load Balancer Types**: Lists ALBs, NLBs, GWLBs, and Classic ELBs
- **Detailed Output**: Shows load balancer name, type, scheme (internet-facing/internal), and DNS name
- **TLS Certificate Information**: Display certificate ARNs and domain names with `--show-certificates` and `--show-certificate-domains`
- **Filtering Options**: Filter for internet-facing load balancers only with `--internet-facing-only`
- **Debug Mode**: `--first-only` flag to stop after the first account with load balancers

## Requirements

- Python 3.9+
- AWS CLI v2 configured with SSO
- Valid AWS SSO profile configured
- `SecurityAudit` role provisioned in target accounts (read-only access)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/mcgroarty/aws-enumerate-elbs.git
   cd aws-enumerate-elbs
   ```

2. Ensure AWS CLI v2 is installed and SSO is configured:
   ```bash
   aws configure sso
   ```

## Usage

### Basic Usage

Run with your default SSO profile (scans us-west-2 by default):
```bash
./enumerate-elbs.py
```

### Specify Regions

Scan specific regions (comma-separated):
```bash
./enumerate-elbs.py --regions us-east-1,us-west-2,eu-west-1
```

### Specify a Profile

Use a specific AWS SSO profile:
```bash
AWS_PROFILE=my-sso-profile ./enumerate-elbs.py
```

### Filter Internet-Facing Load Balancers

Show only internet-facing load balancers:
```bash
./enumerate-elbs.py --internet-facing-only
```

### Show TLS Certificates

Display certificate ARNs attached to load balancers:
```bash
./enumerate-elbs.py --show-certificates
```

### Show Certificate Domain Names

Display domain names for TLS certificates:
```bash
./enumerate-elbs.py --show-certificate-domains
```

### Combined Options

Combine options for specific queries:
```bash
# Show internet-facing load balancers with certificate domains in us-west-2
./enumerate-elbs.py --internet-facing-only --show-certificate-domains --regions us-west-2
```

### Debug Mode

Stop after finding the first account with load balancers (useful for testing):
```bash
./enumerate-elbs.py --first-only
```

### Help

View all available options:
```bash
./enumerate-elbs.py --help
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

### Customizing Regions

Edit the `REGIONS` list in the script to change which regions are scanned:
```python
REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
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
4. **Enumeration**: Uses the temporary credentials to query load balancers in each configured region.
5. **Output**: Displays all load balancers with their key details.

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
- Check that load balancers exist in the configured regions
- Try `--first-only` flag to test on a single account

## License

MIT
