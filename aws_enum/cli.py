"""CLI helpers and main entry point."""

import argparse

REGIONS = ["us-west-2"]


def main():
    """Main entry point for CLI."""
    from .accounts import enumerate_accounts
    from .ecs import enumerate_ecs
    from .iam import enumerate_iam
    from .loadbalancers import enumerate_loadbalancers
    from .route53 import enumerate_route53

    parser = argparse.ArgumentParser(
        description="Enumerate various AWS resources across all AWS SSO accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Keep commands sorted alphabetically
        epilog="""Available commands:
  accounts         List all AWS SSO accounts and available roles
  ecs              Enumerate running ECS containers
  iam              Enumerate IAM summaries and users
  loadbalancers    Enumerate ALBs, NLBs, and Classic ELBs
  route53          Enumerate Route53 hosted zones

For help on a specific command, use:
  %(prog)s COMMAND --help

Examples:
  %(prog)s accounts                         # List all accounts and roles
  %(prog)s ecs                              # List all ECS containers
  %(prog)s iam                              # Show IAM summary per account
  %(prog)s loadbalancers                    # List all load balancers
  %(prog)s route53                          # List all Route53 hosted zones
  AWS_PROFILE=prod %(prog)s accounts        # Use specific SSO profile
        """,
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", metavar="COMMAND"
    )
    subparsers.required = True

    # =========================================================================
    # Subcommands (keep sorted alphabetically)
    # =========================================================================

    # Accounts command
    accounts_parser = subparsers.add_parser(
        "accounts",
        help="List all AWS SSO accounts and available roles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                              # List accounts (names and IDs only)
  %(prog)s --show-roles                 # Show detailed role information
  %(prog)s --include-org                # Include organization-wide account list
  %(prog)s --show-roles --include-org   # Full details with organization accounts
  AWS_PROFILE=prod %(prog)s             # Use specific SSO profile
        """,
    )
    accounts_parser.add_argument(
        "--show-roles",
        action="store_true",
        help="Show detailed role information for each account",
    )
    accounts_parser.add_argument(
        "--include-org",
        action="store_true",
        help="Include organization-wide account listing "
        "(requires AWS Organizations permissions)",
    )

    # ECS command
    ecs_parser = subparsers.add_parser(
        "ecs",
        help="Enumerate running ECS containers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                                         # Enumerate all accounts
  %(prog)s --accounts "Production,Staging"         # Check specific accounts only
  %(prog)s --accounts 123456789012                 # Check by account ID(s)
  %(prog)s --first-only                            # Stop after first account with containers
  %(prog)s --show-tags                             # Display task tags
  %(prog)s --min-age-days 7                        # Only show tasks older than 7 days
  %(prog)s --min-age-days 0.5                      # Only show tasks older than 12 hours
  AWS_PROFILE=prod %(prog)s                        # Use specific SSO profile
        """,
    )
    ecs_parser.add_argument(
        "--first-only",
        action="store_true",
        help="Stop after finding the first account with ECS containers "
        "(useful for debugging)",
    )
    ecs_parser.add_argument(
        "--show-tags", action="store_true", help="Display tags for ECS tasks"
    )
    ecs_parser.add_argument(
        "--min-age-days",
        type=float,
        default=None,
        help="Only show tasks older than this many days "
        "(e.g., 7 or 0.5 for 12 hours)",
    )
    ecs_parser.add_argument(
        "--accounts",
        type=str,
        default=None,
        help="Comma-separated list of account names or IDs to check "
        "(default: all accounts)",
    )
    ecs_parser.add_argument(
        "--regions",
        type=str,
        default=",".join(REGIONS),
        help=f"Comma-separated list of AWS regions to scan "
        f"(default: {','.join(REGIONS)})",
    )

    # IAM command
    iam_parser = subparsers.add_parser(
        "iam",
        help="Enumerate IAM summaries and users",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                                         # Show IAM summary per account
  %(prog)s --users                                 # List IAM users
  %(prog)s --role-trust                            # Show role trust relationships
  %(prog)s --role-trust --external-only            # Only show external/suspicious trust
  %(prog)s --users --inactive-days 90              # Users inactive for 90+ days
  %(prog)s --users --no-mfa-only                   # Users without MFA
  %(prog)s --users --has-keys-only                 # Users with active access keys
  %(prog)s --summary --users                       # Show summary and detailed users
  %(prog)s --users --csv iam-users.csv             # Export users to CSV
  %(prog)s --role-trust --csv iam-role-trust.csv   # Export role trust to CSV
  %(prog)s --accounts "Production,Staging"         # Check specific accounts only
  %(prog)s --first-only                            # Stop after first account with findings
  AWS_PROFILE=prod %(prog)s --summary              # Use specific SSO profile
        """,
    )
    iam_parser.add_argument(
        "--summary",
        action="store_true",
        help="Show account-level IAM summary counts",
    )
    iam_parser.add_argument(
        "--users",
        action="store_true",
        help="List IAM users with credential and policy summary details",
    )
    iam_parser.add_argument(
        "--role-trust",
        action="store_true",
        help="List assumable roles and classify suspicious trust relationships",
    )
    iam_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="For detailed reports, show only counts instead of per-user rows",
    )
    iam_parser.add_argument(
        "--inactive-days",
        type=float,
        default=None,
        help="Only show users whose most recent credential activity "
        "is older than this many days",
    )
    iam_parser.add_argument(
        "--no-mfa-only",
        action="store_true",
        help="Only show users without MFA",
    )
    iam_parser.add_argument(
        "--has-keys-only",
        action="store_true",
        help="Only show users with active access keys",
    )
    iam_parser.add_argument(
        "--external-only",
        action="store_true",
        help="For role trust reports, only show external or broad trust relationships",
    )
    iam_parser.add_argument(
        "--org-id",
        type=str,
        default=None,
        help="Optional AWS organization ID for classifying org-scoped role trust",
    )
    iam_parser.add_argument(
        "--csv",
        type=str,
        metavar="FILE",
        default=None,
        help="Export the selected IAM report to CSV",
    )
    iam_parser.add_argument(
        "--accounts",
        type=str,
        default=None,
        help="Comma-separated list of account names or IDs to check "
        "(default: all accounts)",
    )
    iam_parser.add_argument(
        "--first-only",
        action="store_true",
        help="Stop after the first account with IAM findings " "(useful for debugging)",
    )

    # Load balancer command
    lb_parser = subparsers.add_parser(
        "loadbalancers",
        help="Enumerate ALBs, NLBs, and Classic ELBs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                                         # Enumerate all accounts
  %(prog)s --accounts "Production,Staging"         # Check specific accounts only
  %(prog)s --accounts 123456789012                 # Check by account ID(s)
  %(prog)s --first-only                            # Stop after first account with load balancers
  %(prog)s --internet-facing-only                  # Show only internet-facing load balancers
  %(prog)s --show-certificates                     # Display TLS certificates attached to load balancers
  %(prog)s --show-certificate-domains              # Display domain names for TLS certificates
  AWS_PROFILE=prod %(prog)s                        # Use specific SSO profile
        """,
    )
    lb_parser.add_argument(
        "--first-only",
        action="store_true",
        help="Stop after finding the first account with load balancers "
        "(useful for debugging)",
    )
    lb_parser.add_argument(
        "--internet-facing-only",
        action="store_true",
        help="Show only internet-facing load balancers",
    )
    lb_parser.add_argument(
        "--show-certificates",
        action="store_true",
        help="Display TLS certificates attached to load balancers",
    )
    lb_parser.add_argument(
        "--show-certificate-domains",
        action="store_true",
        help="Display domain names for TLS certificates (implies --show-certificates)",
    )
    lb_parser.add_argument(
        "--accounts",
        type=str,
        default=None,
        help="Comma-separated list of account names or IDs to check "
        "(default: all accounts)",
    )
    lb_parser.add_argument(
        "--regions",
        type=str,
        default=",".join(REGIONS),
        help=f"Comma-separated list of AWS regions to scan "
        f"(default: {','.join(REGIONS)})",
    )

    # Route53 command
    route53_parser = subparsers.add_parser(
        "route53",
        help="Enumerate Route53 hosted zones",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                                         # List all hosted zones
  %(prog)s --show-records                          # Show all DNS records
  %(prog)s --show-records --fqdn                   # Show records with fully qualified names
  %(prog)s --show-records --external-only          # Show only external (non-AWS) targets
  %(prog)s --show-records --record-types A,CNAME   # Filter by record type
  %(prog)s --csv records.csv                       # Export all records to CSV
  %(prog)s --public-only                           # Skip private hosted zones
  %(prog)s --accounts "Production,Staging"         # Check specific accounts only
  %(prog)s --first-only                            # Stop after first account with hosted zones
  AWS_PROFILE=prod %(prog)s                        # Use specific SSO profile
        """,
    )
    route53_parser.add_argument(
        "--first-only",
        action="store_true",
        help="Stop after finding the first account with hosted zones "
        "(useful for debugging)",
    )
    route53_parser.add_argument(
        "--show-records",
        action="store_true",
        help="Display DNS records for each hosted zone",
    )
    route53_parser.add_argument(
        "--fqdn",
        action="store_true",
        help="Show fully qualified domain names (useful for scripting)",
    )
    route53_parser.add_argument(
        "--csv",
        type=str,
        metavar="FILE",
        default=None,
        help="Export records to CSV file (implies --show-records)",
    )
    route53_parser.add_argument(
        "--external-only",
        action="store_true",
        help="Only show records pointing to non-AWS targets "
        "(implies --show-records)",
    )
    route53_parser.add_argument(
        "--public-only",
        action="store_true",
        help="Only show public hosted zones (skip private zones)",
    )
    route53_parser.add_argument(
        "--record-types",
        type=str,
        default=None,
        help="Comma-separated list of record types to show (e.g., A,CNAME,MX)",
    )
    route53_parser.add_argument(
        "--accounts",
        type=str,
        default=None,
        help="Comma-separated list of account names or IDs to check "
        "(default: all accounts)",
    )

    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:  # Argument parsing error
            # Keep commands sorted alphabetically
            print("\nAvailable commands:")
            print("  accounts         List all AWS SSO accounts and available roles")
            print("  ecs              Enumerate running ECS containers")
            print("  iam              Enumerate IAM summaries and users")
            print("  loadbalancers    Enumerate ALBs, NLBs, and Classic ELBs")
            print("  route53          Enumerate Route53 hosted zones")
            print(f"\nFor more information, run: {parser.prog} --help")
        raise

    # Route to appropriate command handler
    if args.command == "accounts":
        enumerate_accounts(args)
    elif args.command == "loadbalancers":
        enumerate_loadbalancers(args)
    elif args.command == "ecs":
        enumerate_ecs(args)
    elif args.command == "iam":
        enumerate_iam(args)
    elif args.command == "route53":
        enumerate_route53(args)


if __name__ == "__main__":
    main()
