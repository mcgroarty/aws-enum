"""Route53 DNS enumeration."""

import re

from .accounts import ROLE_NAME, get_enumerable_accounts, get_role_credentials
from .cli import make_aws_env, run_aws_cli

# Patterns for AWS-managed DNS targets (used for external detection)
AWS_DNS_PATTERNS = [
    r"\.elb\.amazonaws\.com$",
    r"\.elb\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$",
    r"\.cloudfront\.net$",
    r"\.s3\.amazonaws\.com$",
    r"\.s3-[a-z]+-[a-z]+-\d\.amazonaws\.com$",
    r"\.s3\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$",
    r"\.rds\.amazonaws\.com$",
    r"\.cache\.amazonaws\.com$",
    r"\.execute-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$",
    r"\.awsglobalaccelerator\.com$",
    r"\.acm-validations\.aws\.$",  # ACM certificate validation
    r"\.acm-validations\.aws$",
    r"\.amazonaws\.com$",
]

AWS_DNS_REGEX = [re.compile(pattern, re.IGNORECASE) for pattern in AWS_DNS_PATTERNS]


def is_aws_target(target: str) -> bool:
    """Check if a DNS target is an AWS-managed resource."""
    for pattern in AWS_DNS_REGEX:
        if pattern.search(target):
            return True
    return False


def list_hosted_zones(env: dict) -> list[dict]:
    """List all Route53 hosted zones."""
    data = run_aws_cli(["route53", "list-hosted-zones"], env)
    return data.get("HostedZones", []) if data else []


def list_resource_record_sets(zone_id: str, env: dict) -> list[dict]:
    """List all resource record sets for a hosted zone (handles pagination)."""
    all_records = []
    next_record_name = None
    next_record_type = None

    while True:
        args = ["route53", "list-resource-record-sets", "--hosted-zone-id", zone_id]
        if next_record_name:
            args.extend(["--start-record-name", next_record_name])
        if next_record_type:
            args.extend(["--start-record-type", next_record_type])

        data = run_aws_cli(args, env)
        if not data:
            break

        all_records.extend(data.get("ResourceRecordSets", []))

        if not data.get("IsTruncated", False):
            break

        next_record_name = data.get("NextRecordName")
        next_record_type = data.get("NextRecordType")

    return all_records


def enumerate_route53(args):
    """Enumerate Route53 hosted zones across all AWS SSO accounts."""
    from .auth import get_access_token, get_sso_profile
    from .client import set_sso_region

    profile = get_sso_profile()
    access_token, sso_region = get_access_token(profile)
    set_sso_region(sso_region)

    print("SSO token valid. Enumerating Route53 hosted zones...\n")

    # --external-only implies --show-records, --csv implies --show-records
    show_records = args.show_records or args.external_only or args.csv

    # --csv implies --fqdn for the CSV output
    csv_file = None
    csv_writer = None
    if args.csv:
        import csv

        csv_file = open(args.csv, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(
            [
                "account_name",
                "account_id",
                "zone_name",
                "zone_id",
                "zone_type",
                "record_type",
                "record_name",
                "target",
                "is_external",
            ]
        )

    # Parse account filter if specified
    account_filter = None
    if args.accounts:
        account_filter = set(
            a.strip().lower() for a in args.accounts.split(",") if a.strip()
        )

    # Parse record type filter if specified
    record_type_filter = None
    if args.record_types:
        record_type_filter = set(
            t.strip().upper() for t in args.record_types.split(",") if t.strip()
        )

    # Get accounts with roles using shared function
    enumerable_accounts = get_enumerable_accounts(access_token)

    # Filter accounts if specified
    if account_filter:
        filtered_accounts = []
        for account, roles, is_master in enumerable_accounts:
            account_id = account["accountId"]
            account_name = account.get("accountName", "Unknown")
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

        # Check for SecurityAudit role
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

        # Enumerate Route53 hosted zones (global service, no region needed)
        hosted_zones = list_hosted_zones(env)
        found_zones = False

        if hosted_zones:
            for zone in hosted_zones:
                zone_name = zone.get("Name", "Unknown").rstrip(".")
                zone_id = zone.get("Id", "").replace("/hostedzone/", "")
                record_count = zone.get("ResourceRecordSetCount", 0)
                is_private = zone.get("Config", {}).get("PrivateZone", False)
                zone_type = "private" if is_private else "public"

                # Skip private zones if --public-only
                if args.public_only and is_private:
                    continue

                print(
                    f"  {zone_name:50} {zone_id:20} "
                    f"{zone_type:8} {record_count:4} records"
                )
                found_zones = True

                # Show records if requested
                if show_records:
                    records = list_resource_record_sets(zone_id, env)
                    external_count = 0
                    shown_count = 0

                    for record in records:
                        record_type = record.get("Type", "")
                        record_name = record.get("Name", "").rstrip(".")
                        is_alias = "AliasTarget" in record

                        # Apply record type filter
                        # "ALIAS" in filter matches any alias record
                        if record_type_filter:
                            type_matches = record_type in record_type_filter
                            alias_matches = is_alias and "ALIAS" in record_type_filter
                            if not type_matches and not alias_matches:
                                continue

                        # Get target value(s)
                        values = []
                        if is_alias:
                            # ALIAS record
                            record_display_type = "ALIAS"
                            # is_external = False  # ALIAS records are always AWS-managed
                        elif "ResourceRecords" in record:
                            # Standard record
                            values = [
                                rr.get("Value", "")
                                for rr in record.get("ResourceRecords", [])
                            ]
                            record_display_type = record_type
                        else:
                            continue

                        # Format the record name
                        # Use FQDN if --fqdn specified, otherwise shorten
                        if args.fqdn:
                            display_name = record_name
                        elif record_name == zone_name:
                            display_name = "@"
                        elif record_name.endswith("." + zone_name):
                            display_name = record_name[: -len(zone_name) - 1]
                        else:
                            display_name = record_name

                        # Handle ALIAS records (single value)
                        if is_alias:
                            target = (
                                record["AliasTarget"].get("DNSName", "").rstrip(".")
                            )
                            is_external = False  # ALIAS records are always AWS-managed

                            # Skip non-external if --external-only
                            if args.external_only and not is_external:
                                continue

                            # Write to CSV if enabled
                            if csv_writer:
                                csv_writer.writerow(
                                    [
                                        account_name,
                                        account_id,
                                        zone_name,
                                        zone_id,
                                        zone_type,
                                        record_display_type,
                                        record_name,
                                        target,
                                        "no",
                                    ]
                                )

                            # Print record
                            print(
                                f"    {record_display_type:6} "
                                f"{display_name:30} → {target}"
                            )
                            shown_count += 1
                        else:
                            # Handle standard records (potentially multiple values)
                            for value in values:
                                target = value
                                is_external = False
                                if record_type in ["CNAME", "MX"]:
                                    # For MX, extract the server part (after priority)
                                    check_target = (
                                        target.split()[-1]
                                        if record_type == "MX"
                                        else target
                                    )
                                    is_external = not is_aws_target(check_target)

                                # Skip non-external if --external-only
                                if args.external_only and not is_external:
                                    continue

                                if is_external:
                                    external_count += 1

                                # Write to CSV if enabled (always uses FQDN)
                                if csv_writer:
                                    csv_writer.writerow(
                                        [
                                            account_name,
                                            account_id,
                                            zone_name,
                                            zone_id,
                                            zone_type,
                                            record_display_type,
                                            record_name,  # Always FQDN in CSV
                                            target,
                                            "yes" if is_external else "no",
                                        ]
                                    )

                                # Print record
                                external_flag = " 🔶 External" if is_external else ""
                                print(
                                    f"    {record_display_type:6} "
                                    f"{display_name:30} → {target}{external_flag}"
                                )
                                shown_count += 1

                    if args.external_only and external_count == 0:
                        print("    (no external records)")
                    elif shown_count == 0 and record_type_filter:
                        print(
                            f"    (no matching records for types: "
                            f"{','.join(record_type_filter)})"
                        )
        else:
            print("  No hosted zones found")

        print()

        # Exit after first account with zones if --first-only is set
        if args.first_only and found_zones:
            print(
                "--first-only specified. "
                "Stopping after first account with hosted zones."
            )
            break

    # Close CSV file if opened
    if csv_file:
        csv_file.close()
        print(f"CSV output written to: {args.csv}")
