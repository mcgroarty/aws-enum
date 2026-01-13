#!/usr/bin/env python3
"""
AWS Resource Enumeration Tool

Enumerates various AWS resources across all AWS accounts accessible via AWS SSO.

Features:
- Automatic SSO authentication with token caching
- Multi-account enumeration using SecurityAudit role
- Multi-region support
- Command-based interface for different resource types

Requirements:
- AWS CLI v2 configured with SSO
- Valid AWS SSO profile (set via AWS_PROFILE or defaults to 'default')
- SecurityAudit role provisioned in target accounts

Usage:
    # Enumerate load balancers with default profile
    ./enumerate-elbs.py loadbalancers
    
    # Use specific SSO profile
    AWS_PROFILE=my-sso-profile ./enumerate-elbs.py loadbalancers
    
    # Show help for available commands
    ./enumerate-elbs.py --help

The script will automatically prompt for SSO login if no valid token is found.
"""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

ROLE_NAME = "SecurityAudit"
REGIONS = ["us-west-2"]


def get_sso_profile() -> str:
    """Get SSO profile from environment or default."""
    import os
    return os.environ.get("AWS_PROFILE", "default")


def get_cached_access_token() -> Optional[str]:
    """Read valid access token from SSO cache."""
    sso_cache_dir = Path.home() / ".aws" / "sso" / "cache"
    
    if not sso_cache_dir.exists():
        return None
    
    for cache_file in sso_cache_dir.glob("*.json"):
        try:
            data = json.loads(cache_file.read_text())
            access_token = data.get("accessToken")
            expires_at = data.get("expiresAt")
            
            if not access_token or not expires_at:
                continue
            
            # Parse expiration and check validity
            exp_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp_time > datetime.now(timezone.utc):
                return access_token
        except (json.JSONDecodeError, ValueError, KeyError):
            continue
    
    return None


def sso_login(profile: str) -> bool:
    """Initiate SSO login flow."""
    print(f"No valid SSO token found. Initiating login for profile '{profile}'...")
    result = subprocess.run(
        ["aws", "sso", "login", "--profile", profile],
        capture_output=False
    )
    return result.returncode == 0


def get_access_token(profile: str) -> str:
    """Get valid access token, triggering login if needed."""
    token = get_cached_access_token()
    
    if token:
        return token
    
    if not sso_login(profile):
        print("ERROR: SSO login failed.", file=sys.stderr)
        sys.exit(1)
    
    token = get_cached_access_token()
    if not token:
        print("ERROR: Still no valid token after login.", file=sys.stderr)
        sys.exit(1)
    
    return token


def aws_sso_command(args: list[str], access_token: str) -> Optional[Union[dict, list]]:
    """Run an AWS SSO command with the access token."""
    result = subprocess.run(
        ["aws"] + args + ["--output", "json"],
        capture_output=True,
        text=True,
        env={**dict(__import__("os").environ), "AWS_ACCESS_TOKEN": access_token}
    )
    
    if result.returncode != 0:
        return None
    
    return json.loads(result.stdout)


def list_accounts(access_token: str) -> list[dict]:
    """List all accounts accessible via SSO."""
    result = subprocess.run(
        ["aws", "sso", "list-accounts", "--access-token", access_token, "--output", "json"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"ERROR: Failed to list accounts: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    
    return json.loads(result.stdout).get("accountList", [])


def list_account_roles(account_id: str, access_token: str) -> list[str]:
    """List available roles for an account."""
    result = subprocess.run(
        ["aws", "sso", "list-account-roles",
         "--account-id", account_id,
         "--access-token", access_token,
         "--output", "json"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        return []
    
    data = json.loads(result.stdout)
    return [role["roleName"] for role in data.get("roleList", [])]


def get_role_credentials(account_id: str, role_name: str, access_token: str) -> Optional[dict]:
    """Get temporary credentials for a role."""
    result = subprocess.run(
        ["aws", "sso", "get-role-credentials",
         "--account-id", account_id,
         "--role-name", role_name,
         "--access-token", access_token,
         "--output", "json"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        return None
    
    return json.loads(result.stdout).get("roleCredentials")


def make_aws_env(credentials: dict) -> dict:
    """Create environment dict with AWS credentials."""
    import os
    env = dict(os.environ)
    env["AWS_ACCESS_KEY_ID"] = credentials["accessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = credentials["secretAccessKey"]
    env["AWS_SESSION_TOKEN"] = credentials["sessionToken"]
    # Clear profile to avoid conflicts
    env.pop("AWS_PROFILE", None)
    return env


def list_elbv2(region: str, env: dict) -> list[dict]:
    """List ALB/NLB/GWLB in a region."""
    result = subprocess.run(
        ["aws", "elbv2", "describe-load-balancers", "--region", region, "--output", "json"],
        capture_output=True,
        text=True,
        env=env
    )
    
    if result.returncode != 0:
        return []
    
    return json.loads(result.stdout).get("LoadBalancers", [])


def list_elb_classic(region: str, env: dict) -> list[dict]:
    """List Classic ELBs in a region."""
    result = subprocess.run(
        ["aws", "elb", "describe-load-balancers", "--region", region, "--output", "json"],
        capture_output=True,
        text=True,
        env=env
    )
    
    if result.returncode != 0:
        return []
    
    return json.loads(result.stdout).get("LoadBalancerDescriptions", [])


def get_elbv2_certificates(lb_arn: str, region: str, env: dict) -> list[str]:
    """Get TLS certificates for an ALB/NLB."""
    result = subprocess.run(
        ["aws", "elbv2", "describe-listeners",
         "--load-balancer-arn", lb_arn,
         "--region", region,
         "--output", "json"],
        capture_output=True,
        text=True,
        env=env
    )
    
    if result.returncode != 0:
        return []
    
    certificates = []
    data = json.loads(result.stdout)
    for listener in data.get("Listeners", []):
        if listener.get("Protocol") in ["HTTPS", "TLS"]:
            for cert in listener.get("Certificates", []):
                cert_arn = cert.get("CertificateArn")
                if cert_arn:
                    certificates.append(cert_arn)
    
    return certificates


def get_classic_elb_certificates(lb_name: str, region: str, env: dict) -> list[str]:
    """Get TLS certificates for a Classic ELB."""
    result = subprocess.run(
        ["aws", "elb", "describe-load-balancers",
         "--load-balancer-names", lb_name,
         "--region", region,
         "--output", "json"],
        capture_output=True,
        text=True,
        env=env
    )
    
    if result.returncode != 0:
        return []
    
    certificates = []
    data = json.loads(result.stdout)
    for lb in data.get("LoadBalancerDescriptions", []):
        for listener in lb.get("ListenerDescriptions", []):
            listener_data = listener.get("Listener", {})
            if listener_data.get("Protocol") in ["HTTPS", "SSL"]:
                cert_arn = listener_data.get("SSLCertificateId")
                if cert_arn:
                    certificates.append(cert_arn)
    
    return certificates


def get_certificate_domains(cert_arn: str, region: str, env: dict) -> list[str]:
    """Get domain names for a certificate from ACM."""
    result = subprocess.run(
        ["aws", "acm", "describe-certificate",
         "--certificate-arn", cert_arn,
         "--region", region,
         "--output", "json"],
        capture_output=True,
        text=True,
        env=env
    )
    
    if result.returncode != 0:
        return []
    
    data = json.loads(result.stdout)
    cert_data = data.get("Certificate", {})
    domains = []
    
    # Get the primary domain
    domain_name = cert_data.get("DomainName")
    if domain_name:
        domains.append(domain_name)
    
    # Get subject alternative names (SANs)
    sans = cert_data.get("SubjectAlternativeNames", [])
    for san in sans:
        if san not in domains:
            domains.append(san)
    
    return domains


def list_org_accounts(region: str = "us-east-1") -> Optional[list[dict]]:
    """List all accounts in the organization using AWS Organizations API."""
    result = subprocess.run(
        ["aws", "organizations", "list-accounts", "--region", region, "--output", "json"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        return None
    
    try:
        data = json.loads(result.stdout)
        return data.get("Accounts", [])
    except json.JSONDecodeError:
        return None


def get_master_account_id() -> Optional[str]:
    """Get the master account ID from AWS Organizations."""
    try:
        # Try to get organization info using current credentials
        result = subprocess.run(
            ["aws", "organizations", "describe-organization", "--region", "us-east-1", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("Organization", {}).get("MasterAccountId")
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None


def get_account_roles_with_limited_concurrency(accounts, access_token):
    """Get roles for multiple accounts with limited concurrency to avoid rate limits."""
    def get_single_account_roles(account):
        account_id = account["accountId"]
        roles = list_account_roles(account_id, access_token)
        return account_id, roles
    
    account_roles = {}
    print(f"  Checking roles for {len(accounts)} accounts (4-way concurrency)...", end="", flush=True)
    
    # Use limited concurrency to avoid overwhelming AWS SSO API
    with ThreadPoolExecutor(max_workers=4) as executor:
        # Submit all role-checking tasks
        future_to_account = {
            executor.submit(get_single_account_roles, account): account 
            for account in accounts
        }
        
        completed = 0
        for future in as_completed(future_to_account):
            account = future_to_account[future]
            try:
                account_id, roles = future.result()
                account_roles[account_id] = roles
                completed += 1
                
                # Show progress more frequently with parallel processing
                if completed % 4 == 0 or completed == len(accounts):
                    print(".", end="", flush=True)
                    
            except Exception as e:
                print(f"\n    ⚠️  Error for {account.get('accountName', account['accountId'])}: {e}")
                account_roles[account["accountId"]] = []
                completed += 1
    
    print(" done!")
    return account_roles


def get_enumerable_accounts(access_token: str, show_progress: bool = True) -> list[tuple[dict, list[str], bool]]:
    """
    Get all SSO accounts with their roles and master account status.
    
    This is the shared function used by both 'accounts' and 'loadbalancers' commands.
    
    Args:
        access_token: Valid SSO access token
        show_progress: Whether to print progress messages
    
    Returns:
        List of tuples: (account_dict, roles_list, is_master)
        Sorted with master account first, then ready accounts, then non-ready, all alphabetically.
    """
    accounts = list_accounts(access_token)
    
    if not accounts:
        return []
    
    # Get master account ID and roles concurrently (limited concurrency for roles)
    if show_progress:
        print("  Identifying master account and checking roles...")
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        master_future = executor.submit(get_master_account_id)
        roles_future = executor.submit(get_account_roles_with_limited_concurrency, accounts, access_token)
        
        master_account_id = master_future.result()
        account_roles = roles_future.result()
    
    # Organize results
    account_status = []
    master_account = None
    
    if show_progress:
        print("  Organizing accounts...", end="", flush=True)
    
    for account in accounts:
        account_id = account["accountId"]
        roles = account_roles.get(account_id, [])
        is_master = (account_id == master_account_id) if master_account_id else False
        
        if is_master:
            master_account = (account, roles, is_master)
        else:
            account_status.append((account, roles, is_master))
    
    if show_progress:
        print(" done!")
    
    # Sort non-master accounts: ready accounts first (has ROLE_NAME), then alphabetically by name
    account_status.sort(key=lambda x: (ROLE_NAME not in x[1], x[0].get("accountName", "Unknown").lower()))
    
    # Put master account at the top if found
    if master_account:
        account_status.insert(0, master_account)
    
    return account_status


def enumerate_accounts(args):
    """List all AWS SSO accounts and their available roles."""
    profile = get_sso_profile()
    access_token = get_access_token(profile)
    
    if args.include_org:
        print("SSO token valid. Listing organization accounts and SSO accessible accounts...\n")
        
        # Try to get organization accounts first
        org_accounts = list_org_accounts()
        if org_accounts:
            print("=== ORGANIZATION ACCOUNTS (via AWS Organizations API) ===")
            sso_account_ids = set()
            
            # Get SSO accounts for comparison
            sso_accounts = list_accounts(access_token)
            for acc in sso_accounts:
                sso_account_ids.add(acc["accountId"])
            
            for account in org_accounts:
                account_id = account["Id"]
                account_name = account.get("Name", "Unknown")
                status = account.get("Status", "Unknown")
                
                sso_access = "✅ SSO Access" if account_id in sso_account_ids else "❌ No SSO Access"
                print(f"{account_name:40} ({account_id}) [{status}] {sso_access}")
            
            print(f"\nTotal organization accounts: {len(org_accounts)}")
            print(f"Accessible via SSO: {len(sso_account_ids)}")
            print("\n" + "="*70)
        else:
            print("⚠️  Could not retrieve organization accounts. You may not have Organizations permissions.")
            print("Falling back to SSO-only listing...\n")
    else:
        print("SSO token valid. Listing accounts...\n")
    
    # Get accounts with roles using shared function
    enumerable_accounts = get_enumerable_accounts(access_token)
    
    if not enumerable_accounts:
        print("No SSO accessible accounts found.")
        return
    
    if args.include_org:
        print("=== SSO ACCESSIBLE ACCOUNTS ===")
    
    # Simple mode (default): just account names and IDs
    if not args.show_roles:
        ready_count = 0
        master_found = False
        for account, roles, is_master in enumerable_accounts:
            account_id = account["accountId"]
            account_name = account.get("accountName", "Unknown")
            has_security_audit = ROLE_NAME in roles
            
            if has_security_audit:
                if is_master:
                    status_icon = "🏛️"  # Master account indicator
                    master_found = True
                else:
                    status_icon = "✅"
                ready_count += 1
            else:
                status_icon = "❌"
            
            print(f"{status_icon} {account_name:40} ({account_id})")
        
        print(f"\nTotal accounts: {len(enumerable_accounts)}")
        print(f"Ready for enumeration: {ready_count}")
        if master_found:
            print("🏛️ = Master/Management account (can manage organization)")
        print(f"\nTip: Use --show-roles to see detailed role information")
        return
    
    # Detailed mode: show roles and status
    for account, roles, is_master in enumerable_accounts:
        account_id = account["accountId"]
        account_name = account.get("accountName", "Unknown")
        has_security_audit = ROLE_NAME in roles
        
        master_indicator = " [MASTER ACCOUNT]" if is_master else ""
        print(f"=== {account_name} ({account_id}){master_indicator} ===")
        
        if roles:
            print("  Available roles:")
            for role in sorted(roles):
                # Highlight the role we use for enumeration
                if role == ROLE_NAME:
                    print(f"    {role} ✓ (used by enumeration commands)")
                else:
                    print(f"    {role}")
        else:
            print("  No roles available")
        
        # Show role access status
        if has_security_audit:
            status_msg = f"  Status: ✅ Ready for enumeration (has {ROLE_NAME} role)"
            if is_master:
                status_msg += "\n  🏛️ Master/Management account (can manage organization)"
            print(status_msg)
        else:
            print(f"  Status: ❌ Cannot enumerate (missing {ROLE_NAME} role)")
        
        print()


def enumerate_loadbalancers(args):
    """Enumerate load balancers across all AWS SSO accounts."""
    profile = get_sso_profile()
    access_token = get_access_token(profile)
    
    print("SSO token valid. Enumerating accounts...\n")
    
    # Parse regions from command line
    regions = [r.strip() for r in args.regions.split(',') if r.strip()]
    
    # Get accounts with roles using shared function
    enumerable_accounts = get_enumerable_accounts(access_token)
    
    for account, roles, is_master in enumerable_accounts:
        account_id = account["accountId"]
        account_name = account.get("accountName", "Unknown")
        
        print(f"=== {account_name} ({account_id}) ===")
        
        # Check for SecurityAudit role (already have roles from shared function)
        if ROLE_NAME not in roles:
            print(f"  ERROR: {ROLE_NAME} role not provisioned. Skipping.")
            print(f"  Available roles: {', '.join(roles)}")
            print()
            continue
        
        # Get credentials
        credentials = get_role_credentials(account_id, ROLE_NAME, access_token)
        
        if not credentials:
            print(f"  ERROR: Failed to get credentials for {ROLE_NAME}")
            print()
            continue
        
        env = make_aws_env(credentials)
        
        # Enumerate load balancers per region
        found_load_balancers = False
        for region in regions:
            print(f"  Region: {region}")
            
            # ALB/NLB/GWLB
            elbv2_list = list_elbv2(region, env)
            if elbv2_list:
                # Filter by scheme if requested
                if args.internet_facing_only:
                    elbv2_list = [lb for lb in elbv2_list if lb['Scheme'] == 'internet-facing']
                
                if elbv2_list:
                    print("    ALB/NLB/GWLB:")
                    for lb in elbv2_list:
                        print(f"      {lb['LoadBalancerName']:40} {lb['Type']:12} {lb['Scheme']:15} {lb['DNSName']}")
                        
                        # Show certificates if requested
                        if args.show_certificates or args.show_certificate_domains:
                            certs = get_elbv2_certificates(lb['LoadBalancerArn'], region, env)
                            if certs:
                                for cert in certs:
                                    print(f"        Certificate: {cert}")
                                    if args.show_certificate_domains:
                                        domains = get_certificate_domains(cert, region, env)
                                        if domains:
                                            for domain in domains:
                                                print(f"          Domain: {domain}")
                                        else:
                                            print(f"          Domain: Unable to retrieve")
                            else:
                                print(f"        Certificate: None")
                        
                    found_load_balancers = True
            
            # Classic ELB
            elb_list = list_elb_classic(region, env)
            if elb_list:
                # Filter by scheme if requested
                if args.internet_facing_only:
                    elb_list = [lb for lb in elb_list if lb['Scheme'] == 'internet-facing']
                
                if elb_list:
                    print("    Classic ELB:")
                    for lb in elb_list:
                        print(f"      {lb['LoadBalancerName']:40} {'classic':12} {lb['Scheme']:15} {lb['DNSName']}")
                        
                        # Show certificates if requested
                        if args.show_certificates or args.show_certificate_domains:
                            certs = get_classic_elb_certificates(lb['LoadBalancerName'], region, env)
                            if certs:
                                for cert in certs:
                                    print(f"        Certificate: {cert}")
                                    if args.show_certificate_domains:
                                        domains = get_certificate_domains(cert, region, env)
                                        if domains:
                                            for domain in domains:
                                                print(f"          Domain: {domain}")
                                        else:
                                            print(f"          Domain: Unable to retrieve")
                            else:
                                print(f"        Certificate: None")
                        
                    found_load_balancers = True
        
        print()
        
        # Exit after first account with load balancers if --first-only is set
        if args.first_only and found_load_balancers:
            print("--first-only specified. Stopping after first account with load balancers.")
            break


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate various AWS resources across all AWS SSO accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Available commands:
  accounts         List all AWS SSO accounts and available roles
  loadbalancers    Enumerate ALBs, NLBs, and Classic ELBs

For help on a specific command, use:
  %(prog)s COMMAND --help

Examples:
  %(prog)s accounts                         # List all accounts and roles
  %(prog)s loadbalancers                    # List all load balancers
  %(prog)s loadbalancers --help             # Show load balancer options
  AWS_PROFILE=prod %(prog)s accounts        # Use specific SSO profile
        """
    )
    
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        metavar='COMMAND'
    )
    subparsers.required = True
    
    # Accounts command
    accounts_parser = subparsers.add_parser(
        'accounts',
        help='List all AWS SSO accounts and available roles',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                              # List accounts (names and IDs only)
  %(prog)s --show-roles                 # Show detailed role information
  %(prog)s --include-org                # Include organization-wide account list
  %(prog)s --show-roles --include-org   # Full details with organization accounts
  AWS_PROFILE=prod %(prog)s             # Use specific SSO profile
        """
    )
    accounts_parser.add_argument(
        "--show-roles",
        action="store_true",
        help="Show detailed role information for each account"
    )
    accounts_parser.add_argument(
        "--include-org",
        action="store_true",
        help="Include organization-wide account listing (requires AWS Organizations permissions)"
    )
    
    # Load balancer command
    lb_parser = subparsers.add_parser(
        'loadbalancers',
        help='Enumerate ALBs, NLBs, and Classic ELBs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                                         # Enumerate all accounts
  %(prog)s --first-only                            # Stop after first account with load balancers
  %(prog)s --internet-facing-only                  # Show only internet-facing load balancers
  %(prog)s --show-certificates                     # Display TLS certificates attached to load balancers
  %(prog)s --show-certificate-domains              # Display domain names for TLS certificates
  AWS_PROFILE=prod %(prog)s                        # Use specific SSO profile
        """
    )
    lb_parser.add_argument(
        "--first-only",
        action="store_true",
        help="Stop after finding the first account with load balancers (useful for debugging)"
    )
    lb_parser.add_argument(
        "--internet-facing-only",
        action="store_true",
        help="Show only internet-facing load balancers"
    )
    lb_parser.add_argument(
        "--show-certificates",
        action="store_true",
        help="Display TLS certificates attached to load balancers"
    )
    lb_parser.add_argument(
        "--show-certificate-domains",
        action="store_true",
        help="Display domain names for TLS certificates (implies --show-certificates)"
    )
    lb_parser.add_argument(
        "--regions",
        type=str,
        default=",".join(REGIONS),
        help=f"Comma-separated list of AWS regions to scan (default: {','.join(REGIONS)})"
    )
    
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:  # Argument parsing error
            print("\nAvailable commands:")
            print("  accounts         List all AWS SSO accounts and available roles")
            print("  loadbalancers    Enumerate ALBs, NLBs, and Classic ELBs")
            print(f"\nFor more information, run: {parser.prog} --help")
        raise
    
    # Route to appropriate command handler
    if args.command == 'accounts':
        enumerate_accounts(args)
    elif args.command == 'loadbalancers':
        enumerate_loadbalancers(args)


if __name__ == "__main__":
    main()