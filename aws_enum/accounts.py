"""Account and role enumeration."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import boto3

from .cli import run_aws_cli
from .client import get_sso_client

ROLE_NAME = "SecurityAudit"


def list_accounts(access_token: str) -> list[dict]:
    """List all accounts accessible via SSO."""
    client = get_sso_client()
    accounts = []
    paginator = client.get_paginator("list_accounts")

    for page in paginator.paginate(accessToken=access_token):
        accounts.extend(page.get("accountList", []))

    return accounts


def list_account_roles(account_id: str, access_token: str) -> Optional[list[str]]:
    """List available roles for an account. Returns None on API failure."""
    try:
        client = get_sso_client()
        roles = []
        paginator = client.get_paginator("list_account_roles")

        for page in paginator.paginate(accessToken=access_token, accountId=account_id):
            roles.extend([r["roleName"] for r in page.get("roleList", [])])

        return roles
    except Exception:
        return None


def get_role_credentials(
    account_id: str, role_name: str, access_token: str
) -> Optional[dict]:
    """Get temporary credentials for a role."""
    try:
        client = get_sso_client()
        response = client.get_role_credentials(
            roleName=role_name, accountId=account_id, accessToken=access_token
        )
        return response.get("roleCredentials")
    except Exception:
        return None


def get_master_account_id() -> Optional[str]:
    """Get the master account ID from AWS Organizations."""
    try:
        client = boto3.client("organizations", region_name="us-east-1")
        response = client.describe_organization()
        return response.get("Organization", {}).get("MasterAccountId")
    except Exception:
        return None


def get_account_roles_concurrent(accounts: list[dict], access_token: str):
    """Get roles for multiple accounts with concurrency."""

    def get_single_account_roles(account):
        """Fetch roles for a single account."""
        account_id = account["accountId"]
        roles = list_account_roles(account_id, access_token)
        return account_id, roles if roles is not None else []

    account_roles = {}
    print(
        f"  Checking roles for {len(accounts)} accounts...",
        end="",
        flush=True,
    )

    with ThreadPoolExecutor(max_workers=10) as executor:
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

                if completed % 4 == 0 or completed == len(accounts):
                    print(".", end="", flush=True)

            except Exception as e:
                print(f"\n    ⚠️  Error for {account.get('accountName')}: {e}")
                account_roles[account["accountId"]] = []
                completed += 1

    print(" done!")
    return account_roles


def list_org_accounts(region: str = "us-east-1") -> Optional[list[dict]]:
    """List all accounts in the organization using AWS Organizations API."""
    data = run_aws_cli(["organizations", "list-accounts", "--region", region])
    return data.get("Accounts", []) if data else None


def get_enumerable_accounts(
    access_token: str, show_progress: bool = True
) -> list[tuple[dict, list[str], bool]]:
    """
    Get all SSO accounts with their roles and master account status.

    This is the shared function used by both 'accounts' and 'loadbalancers' commands.

    Args:
        access_token: Valid SSO access token
        show_progress: Whether to print progress messages

    Returns:
        List of tuples: (account_dict, roles_list, is_master)
        Sorted with master account first, then ready accounts, then non-ready,
        all alphabetically.
    """
    start_time = time.time()

    accounts = list_accounts(access_token)

    if not accounts:
        return []

    if show_progress:
        elapsed = time.time() - start_time
        print(f"  Listed {len(accounts)} accounts in {elapsed:.2f}s")

    # Get master account ID and roles concurrently
    if show_progress:
        print("  Identifying master account and checking roles...")

    roles_start = time.time()

    with ThreadPoolExecutor(max_workers=2) as executor:
        master_future = executor.submit(get_master_account_id)
        roles_future = executor.submit(
            get_account_roles_concurrent, accounts, access_token
        )

        master_account_id = master_future.result()
        account_roles = roles_future.result()

    if show_progress:
        elapsed = time.time() - roles_start
        print(f"  Role checking completed in {elapsed:.2f}s")

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

    # Sort non-master accounts: ready accounts first (has ROLE_NAME), then alphabetically
    account_status.sort(
        key=lambda x: (
            ROLE_NAME not in x[1],
            x[0].get("accountName", "Unknown").lower(),
        )
    )

    # Put master account at the top if found
    if master_account:
        account_status.insert(0, master_account)

    return account_status


def enumerate_accounts(args):
    """List all AWS SSO accounts and their available roles."""
    from .auth import get_access_token, get_sso_profile
    from .client import set_sso_region

    profile = get_sso_profile()
    access_token, sso_region = get_access_token(profile)
    set_sso_region(sso_region)

    if args.include_org:
        print(
            "SSO token valid. Listing organization accounts "
            "and SSO accessible accounts...\n"
        )

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

                sso_access = (
                    "✅ SSO Access"
                    if account_id in sso_account_ids
                    else "❌ No SSO Access"
                )
                print(f"{account_name:40} ({account_id}) [{status}] {sso_access}")

            print(f"\nTotal organization accounts: {len(org_accounts)}")
            print(f"Accessible via SSO: {len(sso_account_ids)}")
            print("\n" + "=" * 70)
        else:
            print(
                "⚠️  Could not retrieve organization accounts. "
                "You may not have Organizations permissions."
            )
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
        print("\nTip: Use --show-roles to see detailed role information")
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
                status_msg += (
                    "\n  🏛️ Master/Management account (can manage organization)"
                )
            print(status_msg)
        else:
            print(f"  Status: ❌ Cannot enumerate (missing {ROLE_NAME} role)")

        print()
