"""Load balancer enumeration (ALB, NLB, GWLB, Classic ELB)."""

from .accounts import ROLE_NAME, get_enumerable_accounts, get_role_credentials
from .client import get_client_with_credentials


def list_elbv2(elbv2_client) -> list[dict]:
    """List ALB/NLB/GWLB in a region."""
    load_balancers = []
    paginator = elbv2_client.get_paginator("describe_load_balancers")

    for page in paginator.paginate():
        load_balancers.extend(page.get("LoadBalancers", []))

    return load_balancers


def list_elb_classic(elb_client) -> list[dict]:
    """List Classic ELBs in a region."""
    load_balancers = []
    paginator = elb_client.get_paginator("describe_load_balancers")

    for page in paginator.paginate():
        load_balancers.extend(page.get("LoadBalancerDescriptions", []))

    return load_balancers


def get_elbv2_certificates(lb_arn: str, elbv2_client) -> list[str]:
    """Get TLS certificates for an ALB/NLB."""
    try:
        response = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
    except Exception:
        return []

    certificates = []
    for listener in response.get("Listeners", []):
        if listener.get("Protocol") in ["HTTPS", "TLS"]:
            for cert in listener.get("Certificates", []):
                cert_arn = cert.get("CertificateArn")
                if cert_arn:
                    certificates.append(cert_arn)

    return certificates


def get_classic_elb_certificates(lb_name: str, elb_client) -> list[str]:
    """Get TLS certificates for a Classic ELB."""
    try:
        response = elb_client.describe_load_balancers(LoadBalancerNames=[lb_name])
    except Exception:
        return []

    certificates = []
    for lb in response.get("LoadBalancerDescriptions", []):
        for listener in lb.get("ListenerDescriptions", []):
            listener_data = listener.get("Listener", {})
            if listener_data.get("Protocol") in ["HTTPS", "SSL"]:
                cert_arn = listener_data.get("SSLCertificateId")
                if cert_arn:
                    certificates.append(cert_arn)

    return certificates


def get_certificate_domains(cert_arn: str, acm_client) -> list[str]:
    """Get domain names for a certificate from ACM."""
    try:
        response = acm_client.describe_certificate(CertificateArn=cert_arn)
    except Exception:
        return []

    cert_data = response.get("Certificate", {})
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


def print_certificates(certs: list[str], acm_client, show_domains: bool) -> None:
    """Print certificate information for a load balancer."""
    if not certs:
        print("        Certificate: None")
        return

    for cert in certs:
        print(f"        Certificate: {cert}")
        if show_domains:
            domains = get_certificate_domains(cert, acm_client)
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

        # Enumerate load balancers per region
        found_load_balancers = False
        for region in regions:
            print(f"  Region: {region}")

            # Create regional clients
            elbv2_client = get_client_with_credentials("elbv2", credentials, region)
            elb_client = get_client_with_credentials("elb", credentials, region)
            acm_client = (
                get_client_with_credentials("acm", credentials, region)
                if args.show_certificates or args.show_certificate_domains
                else None
            )

            # ALB/NLB/GWLB
            elbv2_list = list_elbv2(elbv2_client)
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
                                lb["LoadBalancerArn"], elbv2_client
                            )
                            print_certificates(
                                certs, acm_client, args.show_certificate_domains
                            )

                    found_load_balancers = True

            # Classic ELB
            elb_list = list_elb_classic(elb_client)
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
                                lb["LoadBalancerName"], elb_client
                            )
                            print_certificates(
                                certs, acm_client, args.show_certificate_domains
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
