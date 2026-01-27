"""Load balancer enumeration (ALB, NLB, GWLB, Classic ELB)."""

from .accounts import ROLE_NAME, get_enumerable_accounts, get_role_credentials
from .cli import make_aws_env, run_aws_cli


def list_elbv2(region: str, env: dict) -> list[dict]:
    """List ALB/NLB/GWLB in a region."""
    data = run_aws_cli(["elbv2", "describe-load-balancers", "--region", region], env)
    return data.get("LoadBalancers", []) if data else []


def list_elb_classic(region: str, env: dict) -> list[dict]:
    """List Classic ELBs in a region."""
    data = run_aws_cli(["elb", "describe-load-balancers", "--region", region], env)
    return data.get("LoadBalancerDescriptions", []) if data else []


def get_elbv2_certificates(lb_arn: str, region: str, env: dict) -> list[str]:
    """Get TLS certificates for an ALB/NLB."""
    data = run_aws_cli(
        [
            "elbv2",
            "describe-listeners",
            "--load-balancer-arn",
            lb_arn,
            "--region",
            region,
        ],
        env,
    )
    if not data:
        return []

    certificates = []
    for listener in data.get("Listeners", []):
        if listener.get("Protocol") in ["HTTPS", "TLS"]:
            for cert in listener.get("Certificates", []):
                cert_arn = cert.get("CertificateArn")
                if cert_arn:
                    certificates.append(cert_arn)

    return certificates


def get_classic_elb_certificates(lb_name: str, region: str, env: dict) -> list[str]:
    """Get TLS certificates for a Classic ELB."""
    data = run_aws_cli(
        [
            "elb",
            "describe-load-balancers",
            "--load-balancer-names",
            lb_name,
            "--region",
            region,
        ],
        env,
    )
    if not data:
        return []

    certificates = []
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
    data = run_aws_cli(
        [
            "acm",
            "describe-certificate",
            "--certificate-arn",
            cert_arn,
            "--region",
            region,
        ],
        env,
    )
    if not data:
        return []

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


def print_certificates(
    certs: list[str], region: str, env: dict, show_domains: bool
) -> None:
    """Print certificate information for a load balancer."""
    if not certs:
        print("        Certificate: None")
        return

    for cert in certs:
        print(f"        Certificate: {cert}")
        if show_domains:
            domains = get_certificate_domains(cert, region, env)
            if domains:
                for domain in domains:
                    print(f"          Domain: {domain}")
            else:
                print("          Domain: Unable to retrieve")


def enumerate_loadbalancers(args):
    """Enumerate load balancers across all AWS SSO accounts."""
    from .auth import get_access_token, get_sso_profile
    from .client import set_sso_region

    profile = get_sso_profile()
    access_token, sso_region = get_access_token(profile)
    set_sso_region(sso_region)

    print("SSO token valid. Enumerating accounts...\n")

    # Parse regions from command line
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    # Parse account filter if specified
    account_filter = None
    if args.accounts:
        account_filter = set(
            a.strip().lower() for a in args.accounts.split(",") if a.strip()
        )

    # Get accounts with roles using shared function
    enumerable_accounts = get_enumerable_accounts(access_token)

    # Filter accounts if specified
    if account_filter:
        filtered_accounts = []
        for account, roles, is_master in enumerable_accounts:
            account_id = account["accountId"]
            account_name = account.get("accountName", "Unknown")
            # Match on account ID or account name (case-insensitive)
            if (
                account_id.lower() in account_filter
                or account_name.lower() in account_filter
            ):
                filtered_accounts.append((account, roles, is_master))

        if not filtered_accounts:
            print(f"No accounts matched filter: {args.accounts}")
            print("\nAvailable accounts:")
            for account, roles, is_master in enumerable_accounts:
                print(
                    f"  {account.get('accountName', 'Unknown')} ({account['accountId']})"
                )
            return

        enumerable_accounts = filtered_accounts
        print(f"Filtering to {len(enumerable_accounts)} account(s): {args.accounts}\n")

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
                    elbv2_list = [
                        lb for lb in elbv2_list if lb["Scheme"] == "internet-facing"
                    ]

                if elbv2_list:
                    print("    ALB/NLB/GWLB:")
                    for lb in elbv2_list:
                        print(
                            f"      {lb['LoadBalancerName']:40} "
                            f"{lb['Type']:12} {lb['Scheme']:15} {lb['DNSName']}"
                        )

                        if args.show_certificates or args.show_certificate_domains:
                            certs = get_elbv2_certificates(
                                lb["LoadBalancerArn"], region, env
                            )
                            print_certificates(
                                certs, region, env, args.show_certificate_domains
                            )

                    found_load_balancers = True

            # Classic ELB
            elb_list = list_elb_classic(region, env)
            if elb_list:
                # Filter by scheme if requested
                if args.internet_facing_only:
                    elb_list = [
                        lb for lb in elb_list if lb["Scheme"] == "internet-facing"
                    ]

                if elb_list:
                    print("    Classic ELB:")
                    for lb in elb_list:
                        print(
                            f"      {lb['LoadBalancerName']:40} "
                            f"{'classic':12} {lb['Scheme']:15} {lb['DNSName']}"
                        )

                        if args.show_certificates or args.show_certificate_domains:
                            certs = get_classic_elb_certificates(
                                lb["LoadBalancerName"], region, env
                            )
                            print_certificates(
                                certs, region, env, args.show_certificate_domains
                            )

                    found_load_balancers = True

        print()

        # Exit after first account with load balancers if --first-only is set
        if args.first_only and found_load_balancers:
            print(
                "--first-only specified. "
                "Stopping after first account with load balancers."
            )
            break
