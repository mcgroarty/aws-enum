"""ECS container enumeration."""

from datetime import datetime, timezone

from .accounts import ROLE_NAME, get_enumerable_accounts, get_role_credentials
from .client import get_client_with_credentials


def _parse_started_at(started_at: str | datetime) -> datetime | None:
    """Parse task startedAt into a timezone-aware datetime."""
    if isinstance(started_at, datetime):
        if started_at.tzinfo is None:
            return started_at.replace(tzinfo=timezone.utc)
        return started_at
    if not started_at:
        return None
    try:
        return datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def format_age(started_at: str | datetime) -> str:
    """Format task age as human-readable string."""
    try:
        # Parse ISO format timestamp
        start_time = _parse_started_at(started_at)
        if not start_time:
            return "unknown"
        now = datetime.now(timezone.utc)
        delta = now - start_time

        days = delta.days
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60

        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    except (ValueError, TypeError):
        return "unknown"


def get_task_age_days(started_at: str | datetime) -> float:
    """Get task age in days as a float."""
    try:
        start_time = _parse_started_at(started_at)
        if not start_time:
            return 0.0
        now = datetime.now(timezone.utc)
        delta = now - start_time
        return delta.total_seconds() / 86400  # seconds per day
    except (ValueError, TypeError):
        return 0.0


def list_ecs_clusters(ecs_client) -> list[str]:
    """List all ECS clusters in a region."""
    cluster_arns = []
    paginator = ecs_client.get_paginator("list_clusters")

    for page in paginator.paginate():
        cluster_arns.extend(page.get("clusterArns", []))

    return cluster_arns


def list_ecs_services(cluster_arn: str, ecs_client) -> list[str]:
    """List all services in an ECS cluster."""
    service_arns = []
    paginator = ecs_client.get_paginator("list_services")

    for page in paginator.paginate(cluster=cluster_arn):
        service_arns.extend(page.get("serviceArns", []))

    return service_arns


def list_ecs_tasks(
    cluster_arn: str, ecs_client, service_arn: str | None = None
) -> list[str]:
    """List running tasks in an ECS cluster, optionally filtered by service."""
    task_arns = []
    paginator = ecs_client.get_paginator("list_tasks")

    paginate_kwargs = {"cluster": cluster_arn, "desiredStatus": "RUNNING"}
    if service_arn:
        paginate_kwargs["serviceName"] = service_arn

    for page in paginator.paginate(**paginate_kwargs):
        task_arns.extend(page.get("taskArns", []))

    return task_arns


def describe_ecs_tasks(
    cluster_arn: str, task_arns: list[str], ecs_client
) -> list[dict]:
    """Get detailed information about ECS tasks."""
    if not task_arns:
        return []
    try:
        response = ecs_client.describe_tasks(cluster=cluster_arn, tasks=task_arns)
        return response.get("tasks", [])
    except Exception:
        return []


def get_ecs_tags(resource_arn: str, ecs_client) -> dict[str, str]:
    """Get tags for an ECS resource."""
    try:
        response = ecs_client.list_tags_for_resource(resourceArn=resource_arn)
        return {tag["key"]: tag["value"] for tag in response.get("tags", [])}
    except Exception:
        return {}


def enumerate_ecs(args):
    """Enumerate ECS containers across all AWS SSO accounts."""
    from .auth import get_access_token, get_sso_profile
    from .client import set_sso_region

    profile = get_sso_profile()
    access_token, sso_region = get_access_token(profile)
    set_sso_region(sso_region)

    print("SSO token valid. Enumerating ECS containers...\n")

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

        # Enumerate ECS per region
        found_containers = False
        for region in regions:
            print(f"  Region: {region}")

            # Create regional ECS client
            ecs_client = get_client_with_credentials("ecs", credentials, region)

            # Get all clusters
            cluster_arns = list_ecs_clusters(ecs_client)
            if not cluster_arns:
                continue

            for cluster_arn in cluster_arns:
                cluster_name = cluster_arn.split("/")[-1]

                # Get services in the cluster
                service_arns = list_ecs_services(cluster_arn, ecs_client)

                # Track tasks we've seen to avoid duplicates
                seen_task_arns = set()

                # Get tasks for each service
                for service_arn in service_arns:
                    service_name = service_arn.split("/")[-1]

                    # Get service tags once per service (if --show-tags)
                    service_tags = {}
                    if args.show_tags:
                        service_tags = get_ecs_tags(service_arn, ecs_client)

                    task_arns = list_ecs_tasks(cluster_arn, ecs_client, service_arn)

                    if task_arns:
                        tasks = describe_ecs_tasks(cluster_arn, task_arns, ecs_client)
                        for task in tasks:
                            task_arn = task.get("taskArn", "")
                            started_at = task.get("startedAt", "")
                            task_age_days = (
                                get_task_age_days(started_at) if started_at else 0.0
                            )

                            # Skip tasks younger than min-age-days
                            if args.min_age_days and task_age_days < args.min_age_days:
                                seen_task_arns.add(task_arn)
                                continue

                            seen_task_arns.add(task_arn)
                            age_str = (
                                format_age(started_at) if started_at else "unknown"
                            )

                            for container in task.get("containers", []):
                                container_name = container.get("name", "Unknown")
                                status = container.get("lastStatus", "Unknown")
                                image = container.get("image", "Unknown")

                                print(
                                    f"    {cluster_name:25} {service_name:30} "
                                    f"{container_name:25} {status:10} "
                                    f"{age_str:10} {image}"
                                )

                                if args.show_tags:
                                    # Show service tags first, then task tags
                                    if service_tags:
                                        for key, value in sorted(service_tags.items()):
                                            print(f"      Service Tag: {key}={value}")
                                    task_tags = get_ecs_tags(task_arn, ecs_client)
                                    if task_tags:
                                        for key, value in sorted(task_tags.items()):
                                            print(f"      Task Tag: {key}={value}")

                                found_containers = True

                # Get standalone tasks (not associated with a service)
                all_task_arns = list_ecs_tasks(cluster_arn, ecs_client)
                standalone_tasks = [t for t in all_task_arns if t not in seen_task_arns]

                if standalone_tasks:
                    tasks = describe_ecs_tasks(
                        cluster_arn, standalone_tasks, ecs_client
                    )
                    for task in tasks:
                        task_arn = task.get("taskArn", "")
                        started_at = task.get("startedAt", "")
                        task_age_days = (
                            get_task_age_days(started_at) if started_at else 0.0
                        )

                        # Skip tasks younger than min-age-days
                        if args.min_age_days and task_age_days < args.min_age_days:
                            continue

                        age_str = format_age(started_at) if started_at else "unknown"

                        for container in task.get("containers", []):
                            container_name = container.get("name", "Unknown")
                            status = container.get("lastStatus", "Unknown")
                            image = container.get("image", "Unknown")

                            print(
                                f"    {cluster_name:25} {'(standalone)':30} "
                                f"{container_name:25} {status:10} "
                                f"{age_str:10} {image}"
                            )

                            if args.show_tags:
                                task_tags = get_ecs_tags(task_arn, ecs_client)
                                if task_tags:
                                    for key, value in sorted(task_tags.items()):
                                        print(f"      Task Tag: {key}={value}")

                            found_containers = True

        print()

        # Exit after first account with containers if --first-only is set
        if args.first_only and found_containers:
            print(
                "--first-only specified. "
                "Stopping after first account with ECS containers."
            )
            break
