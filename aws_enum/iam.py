"""IAM inventory and summary reporting."""

from __future__ import annotations

import csv
import io
import json
import re
import time
from datetime import datetime, timezone
from urllib.parse import unquote

SUMMARY_CSV_COLUMNS = [
    "account_name",
    "account_id",
    "users",
    "groups",
    "roles",
    "policies",
    "account_mfa_enabled",
    "mfa_devices_in_use",
    "account_access_keys_present",
    "account_password_present",
    "providers",
]

USER_CSV_COLUMNS = [
    "account_name",
    "account_id",
    "user_name",
    "user_arn",
    "created_at",
    "password_enabled",
    "password_last_used",
    "mfa_active",
    "access_key_count",
    "access_key_1_active",
    "access_key_1_last_used",
    "access_key_2_active",
    "access_key_2_last_used",
    "last_activity",
    "groups",
    "attached_policies",
    "inline_policy_count",
    "permissions_boundary",
    "permission_summary",
]

ROLE_TRUST_CSV_COLUMNS = [
    "account_name",
    "account_id",
    "role_name",
    "role_arn",
    "created_at",
    "last_used",
    "trusted_principal_type",
    "trusted_principal",
    "trusted_account_id",
    "trust_scope",
    "is_external",
    "has_external_id_condition",
    "has_org_condition",
    "trust_risk",
    "notes",
]

HYGIENE_CSV_COLUMNS = [
    "account_name",
    "account_id",
    "finding_type",
    "resource_type",
    "resource_name",
    "severity",
    "last_used",
    "details",
]


def _parse_iam_timestamp(value: str | datetime | None) -> datetime | None:
    """Parse an IAM timestamp into a timezone-aware datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if not value:
        return None

    if isinstance(value, str) and value.upper() in {
        "N/A",
        "NOT_SUPPORTED",
        "NO_INFORMATION",
    }:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


def _format_date(value: str | datetime | None) -> str:
    """Format a timestamp as YYYY-MM-DD, or return a stable placeholder."""
    parsed = _parse_iam_timestamp(value)
    if not parsed:
        return "never"
    return parsed.astimezone(timezone.utc).date().isoformat()


def _csv_bool(value: str | bool) -> str:
    """Normalize boolean-like values to yes/no strings for CSV and output."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return "yes" if str(value).strip().upper() == "TRUE" else "no"


def _credential_flag(value: str) -> bool:
    """Interpret a credential report boolean cell."""
    return str(value).strip().upper() == "TRUE"


def _decode_credential_report(content: bytes) -> list[dict[str, str]]:
    """Decode the IAM credential report CSV into row dicts."""
    text = content.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        cleaned = {
            (key or "").strip(): (value or "").strip() for key, value in row.items()
        }
        if cleaned:
            rows.append(cleaned)
    return rows


def _most_recent_activity(report_row: dict[str, str]) -> datetime | None:
    """Return the most recent known password or access-key activity."""
    timestamps = [
        _parse_iam_timestamp(report_row.get("password_last_used")),
        _parse_iam_timestamp(report_row.get("access_key_1_last_used_date")),
        _parse_iam_timestamp(report_row.get("access_key_2_last_used_date")),
    ]
    timestamps = [ts for ts in timestamps if ts is not None]
    if not timestamps:
        return None
    return max(timestamps)


def _is_read_only_policy(policy_name: str) -> bool:
    """Check whether a policy name is clearly read-only."""
    lowered = policy_name.lower()
    return "readonly" in lowered or lowered.startswith("view")


def _classify_permission_summary(
    policy_names: list[str], inline_policy_count: int
) -> str:
    """Classify permissions into coarse reporting buckets."""
    lowered = [name.lower() for name in policy_names]

    if "poweruseraccess" in lowered:
        return "power-user"

    admin_markers = {"administratoraccess", "iamfullaccess"}
    if any(name in admin_markers for name in lowered):
        return "admin-equivalent"

    if lowered and all(_is_read_only_policy(name) for name in policy_names):
        return "read-only"

    if inline_policy_count > 0 or policy_names:
        return "custom/unknown"

    return "none"


def _is_admin_equivalent(permission_summary: str) -> bool:
    """Check whether a coarse permission summary is admin-equivalent."""
    return permission_summary == "admin-equivalent"


def _days_since(value: str | datetime | None) -> float | None:
    """Return age in days from a timestamp-like value."""
    parsed = _parse_iam_timestamp(value)
    if parsed is None:
        return None
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400


def _default_inactive_days(args) -> float:
    """Return the active stale-age threshold for IAM hygiene."""
    return args.inactive_days if args.inactive_days is not None else 90.0


def _service_linked_role(role: dict) -> bool:
    """Check whether a role appears to be AWS service-linked."""
    role_name = role.get("role_name") or role.get("RoleName") or ""
    role_path = role.get("path") or role.get("Path") or ""
    return role_name.startswith("AWSServiceRoleFor") or role_path.startswith(
        "/aws-service-role/"
    )


def _suspicious_name_reason(name: str) -> str:
    """Return a short reason when a principal name looks noteworthy."""
    lowered = name.lower()
    patterns = [
        (r"break[-_ ]?glass", "break-glass naming"),
        (r"emergency", "emergency naming"),
        (r"backdoor", "backdoor naming"),
        (r"temp|temporary", "temporary naming"),
        (r"legacy|old", "legacy naming"),
        (r"vendor|third[-_ ]?party|contractor|external", "external-party naming"),
        (r"debug", "debug naming"),
    ]
    for pattern, reason in patterns:
        if re.search(pattern, lowered):
            return reason
    return ""


def _paginate(iam_client, operation_name: str, result_key: str, **kwargs) -> list:
    """Collect all items from a paginated IAM operation."""
    items = []
    paginator = iam_client.get_paginator(operation_name)
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def _load_credential_report(iam_client) -> list[dict[str, str]]:
    """Generate and retrieve the current account's credential report."""
    iam_client.generate_credential_report()
    last_error = None

    for _ in range(12):
        try:
            response = iam_client.get_credential_report()
            return _decode_credential_report(response["Content"])
        except Exception as exc:
            last_error = exc
            time.sleep(1)

    raise RuntimeError(f"Credential report was not ready after waiting: {last_error}")


def _normalize_to_list(value) -> list:
    """Normalize scalars and tuples into a flat list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _decode_policy_document(document) -> dict:
    """Decode an IAM policy document into a Python dict."""
    if isinstance(document, dict):
        return document
    if not document:
        return {}

    if isinstance(document, str):
        try:
            return json.loads(unquote(document))
        except json.JSONDecodeError:
            return {}

    return {}


def _extract_condition_values(condition: dict | None, key: str) -> list[str]:
    """Collect condition values for a named condition key."""
    if not isinstance(condition, dict):
        return []

    matches = []
    for operator_values in condition.values():
        if not isinstance(operator_values, dict):
            continue
        for condition_key, condition_value in operator_values.items():
            if condition_key.lower() != key.lower():
                continue
            for value in _normalize_to_list(condition_value):
                matches.append(str(value))
    return matches


def _extract_principals(principal) -> list[tuple[str, str]]:
    """Extract principals from a trust policy statement."""
    if principal is None:
        return []

    if principal == "*":
        return [("Wildcard", "*")]

    if isinstance(principal, str):
        return [("Unknown", principal)]

    if not isinstance(principal, dict):
        return []

    principals = []
    for principal_type, principal_values in principal.items():
        for value in _normalize_to_list(principal_values):
            principals.append((str(principal_type), str(value)))
    return principals


def _extract_account_id_from_principal(principal: str) -> str:
    """Extract an AWS account ID from a principal ARN or account string."""
    if re.fullmatch(r"\d{12}", principal):
        return principal

    match = re.search(r":iam::(\d{12}):", principal)
    if match:
        return match.group(1)

    return ""


def _statement_allows_assume_role(statement: dict) -> bool:
    """Check whether a statement allows role assumption."""
    if statement.get("Effect") != "Allow":
        return False

    actions = [str(action) for action in _normalize_to_list(statement.get("Action"))]
    for action in actions:
        if action in {"*", "sts:*"}:
            return True
        if action.startswith("sts:AssumeRole"):
            return True
    return False


def _classify_trust_scope(
    principal_type: str,
    principal: str,
    trusted_account_id: str,
    current_account_id: str,
    has_org_condition: bool,
    org_id: str | None,
    org_condition_values: list[str],
) -> tuple[str, str]:
    """Classify how broad a trust relationship is."""
    principal_type_lower = principal_type.lower()

    if principal_type_lower == "service":
        return "service", "no"

    if principal == "*" or principal_type_lower == "wildcard":
        return "wildcard", "yes"

    if principal_type_lower == "aws":
        if not trusted_account_id:
            return "aws-unknown", "yes"
        if trusted_account_id == current_account_id:
            return "same-account", "no"
        if has_org_condition:
            if org_id and org_id in org_condition_values:
                return "same-org", "no"
            return "org-scoped", "no"
        return "cross-account", "yes"

    if principal_type_lower == "federated":
        if trusted_account_id and trusted_account_id == current_account_id:
            return "federated-local", "no"
        return "federated", "yes"

    return "unknown", "yes"


def _classify_trust_risk(
    trust_scope: str, has_external_id: bool, has_org_condition: bool
) -> str:
    """Classify trust relationships into coarse risk buckets."""
    if trust_scope == "wildcard":
        return "high"
    if trust_scope in {"cross-account", "federated", "aws-unknown", "unknown"}:
        if not has_external_id and not has_org_condition:
            return "high"
        return "medium"
    if trust_scope == "org-scoped":
        return "medium"
    if trust_scope in {"same-account", "same-org", "federated-local"}:
        return "low"
    return "medium"


def _build_role_trust_records(
    account_name: str, account_id: str, iam_client, org_id: str | None = None
) -> list[dict]:
    """Build role-trust records for one account."""
    roles = _paginate(iam_client, "list_roles", "Roles")
    records = []

    for role_summary in roles:
        role_name = role_summary["RoleName"]
        role_detail = iam_client.get_role(RoleName=role_name).get("Role", {})
        policy = _decode_policy_document(role_detail.get("AssumeRolePolicyDocument"))
        statements = _normalize_to_list(policy.get("Statement"))

        for statement in statements:
            if not isinstance(statement, dict):
                continue
            if not _statement_allows_assume_role(statement):
                continue

            condition = statement.get("Condition", {})
            has_external_id = bool(
                _extract_condition_values(condition, "sts:ExternalId")
            )
            org_condition_values = _extract_condition_values(
                condition, "aws:PrincipalOrgID"
            )
            has_org_condition = bool(org_condition_values)

            for principal_type, principal in _extract_principals(
                statement.get("Principal")
            ):
                trusted_account_id = _extract_account_id_from_principal(principal)
                trust_scope, is_external = _classify_trust_scope(
                    principal_type,
                    principal,
                    trusted_account_id,
                    account_id,
                    has_org_condition,
                    org_id,
                    org_condition_values,
                )

                if trust_scope == "service":
                    continue

                notes = []
                if trust_scope == "cross-account":
                    notes.append("cross-account AWS principal")
                elif trust_scope == "wildcard":
                    notes.append("wildcard principal")
                elif trust_scope == "org-scoped":
                    notes.append("org condition present")
                elif trust_scope == "federated":
                    notes.append("federated trust")

                if trust_scope in {"cross-account", "wildcard", "federated"}:
                    if not has_external_id and not has_org_condition:
                        notes.append("no ExternalId or org condition")
                if has_external_id:
                    notes.append("ExternalId condition present")
                if has_org_condition:
                    notes.append(
                        "PrincipalOrgID=" + ",".join(sorted(set(org_condition_values)))
                    )

                records.append(
                    {
                        "account_name": account_name,
                        "account_id": account_id,
                        "role_name": role_name,
                        "role_arn": role_detail.get("Arn", role_summary.get("Arn", "")),
                        "created_at": _format_date(
                            role_detail.get(
                                "CreateDate", role_summary.get("CreateDate")
                            )
                        ),
                        "last_used": _format_date(
                            role_detail.get("RoleLastUsed", {}).get("LastUsedDate")
                        ),
                        "trusted_principal_type": principal_type,
                        "trusted_principal": principal,
                        "trusted_account_id": trusted_account_id,
                        "trust_scope": trust_scope,
                        "is_external": is_external,
                        "has_external_id_condition": "yes" if has_external_id else "no",
                        "has_org_condition": "yes" if has_org_condition else "no",
                        "trust_risk": _classify_trust_risk(
                            trust_scope,
                            has_external_id,
                            has_org_condition,
                        ),
                        "notes": "; ".join(notes),
                    }
                )

    return records


def _build_role_inventory_records(
    account_name: str, account_id: str, iam_client
) -> list[dict]:
    """Build role inventory records for IAM hygiene analysis."""
    roles = _paginate(iam_client, "list_roles", "Roles")
    records = []

    for role_summary in roles:
        role_name = role_summary["RoleName"]
        role_detail = iam_client.get_role(RoleName=role_name).get("Role", {})
        attached_policies = sorted(
            policy["PolicyName"]
            for policy in _paginate(
                iam_client,
                "list_attached_role_policies",
                "AttachedPolicies",
                RoleName=role_name,
            )
        )
        inline_policies = sorted(
            _paginate(
                iam_client, "list_role_policies", "PolicyNames", RoleName=role_name
            )
        )

        records.append(
            {
                "account_name": account_name,
                "account_id": account_id,
                "role_name": role_name,
                "role_arn": role_detail.get("Arn", role_summary.get("Arn", "")),
                "path": role_detail.get("Path", role_summary.get("Path", "")),
                "created_at": _format_date(
                    role_detail.get("CreateDate", role_summary.get("CreateDate"))
                ),
                "last_used": _format_date(
                    role_detail.get("RoleLastUsed", {}).get("LastUsedDate")
                ),
                "attached_policies": attached_policies,
                "inline_policy_count": len(inline_policies),
                "permissions_boundary": role_detail.get("PermissionsBoundary", {}).get(
                    "PermissionsBoundaryArn", ""
                ),
                "permission_summary": _classify_permission_summary(
                    attached_policies,
                    len(inline_policies),
                ),
                "is_service_linked": _service_linked_role(
                    {
                        "role_name": role_name,
                        "path": role_detail.get("Path", role_summary.get("Path", "")),
                    }
                ),
            }
        )

    return records


def _get_group_policy_info(
    group_name: str, iam_client, cache: dict[str, dict[str, list[str] | int]]
) -> dict[str, list[str] | int]:
    """Return cached group policy information."""
    if group_name in cache:
        return cache[group_name]

    attached_policies = sorted(
        policy["PolicyName"]
        for policy in _paginate(
            iam_client,
            "list_attached_group_policies",
            "AttachedPolicies",
            GroupName=group_name,
        )
    )
    inline_policies = sorted(
        _paginate(
            iam_client, "list_group_policies", "PolicyNames", GroupName=group_name
        )
    )

    cache[group_name] = {
        "attached_policies": attached_policies,
        "inline_policy_count": len(inline_policies),
    }
    return cache[group_name]


def _get_account_summary_record(account_name: str, account_id: str, iam_client) -> dict:
    """Build a flat account summary record from IAM GetAccountSummary."""
    summary = iam_client.get_account_summary().get("SummaryMap", {})
    return {
        "account_name": account_name,
        "account_id": account_id,
        "users": summary.get("Users", 0),
        "groups": summary.get("Groups", 0),
        "roles": summary.get("Roles", 0),
        "policies": summary.get("Policies", 0),
        "account_mfa_enabled": "yes" if summary.get("AccountMFAEnabled", 0) else "no",
        "mfa_devices_in_use": summary.get("MFADevicesInUse", 0),
        "account_access_keys_present": "yes"
        if summary.get("AccountAccessKeysPresent", 0)
        else "no",
        "account_password_present": "yes"
        if summary.get("AccountPasswordPresent", 0)
        else "no",
        "providers": summary.get("Providers", 0),
    }


def _build_user_records(account_name: str, account_id: str, iam_client) -> list[dict]:
    """Build IAM user inventory records for one account."""
    credential_rows = _load_credential_report(iam_client)
    user_rows = {
        user["UserName"]: user for user in _paginate(iam_client, "list_users", "Users")
    }
    group_cache: dict[str, dict[str, list[str] | int]] = {}
    records = []

    for row in credential_rows:
        username = row.get("user", "")
        if not username or username == "<root_account>":
            continue

        user_data = user_rows.get(username, {})
        groups = sorted(
            group["GroupName"]
            for group in _paginate(
                iam_client, "list_groups_for_user", "Groups", UserName=username
            )
        )
        attached_policies = sorted(
            policy["PolicyName"]
            for policy in _paginate(
                iam_client,
                "list_attached_user_policies",
                "AttachedPolicies",
                UserName=username,
            )
        )
        inline_policies = sorted(
            _paginate(
                iam_client, "list_user_policies", "PolicyNames", UserName=username
            )
        )

        effective_policy_names = list(attached_policies)
        effective_inline_count = len(inline_policies)
        for group_name in groups:
            group_info = _get_group_policy_info(group_name, iam_client, group_cache)
            effective_policy_names.extend(group_info["attached_policies"])
            effective_inline_count += int(group_info["inline_policy_count"])

        last_activity = _most_recent_activity(row)
        access_key_count = int(
            _credential_flag(row.get("access_key_1_active", ""))
        ) + int(_credential_flag(row.get("access_key_2_active", "")))

        records.append(
            {
                "account_name": account_name,
                "account_id": account_id,
                "user_name": username,
                "user_arn": row.get("arn") or user_data.get("Arn", ""),
                "created_at": _format_date(
                    row.get("user_creation_time") or user_data.get("CreateDate")
                ),
                "password_enabled": _csv_bool(row.get("password_enabled", "")),
                "password_last_used": _format_date(row.get("password_last_used")),
                "mfa_active": _csv_bool(row.get("mfa_active", "")),
                "access_key_count": access_key_count,
                "access_key_1_active": _csv_bool(row.get("access_key_1_active", "")),
                "access_key_1_last_used": _format_date(
                    row.get("access_key_1_last_used_date")
                ),
                "access_key_2_active": _csv_bool(row.get("access_key_2_active", "")),
                "access_key_2_last_used": _format_date(
                    row.get("access_key_2_last_used_date")
                ),
                "last_activity": _format_date(last_activity),
                "groups": ", ".join(groups),
                "attached_policies": ", ".join(sorted(set(attached_policies))),
                "inline_policy_count": effective_inline_count,
                "permissions_boundary": user_data.get("PermissionsBoundary", {}).get(
                    "PermissionsBoundaryArn", ""
                ),
                "permission_summary": _classify_permission_summary(
                    sorted(set(effective_policy_names)),
                    effective_inline_count,
                ),
            }
        )

    return records


def _user_matches_filters(record: dict, args) -> bool:
    """Apply CLI filters to a user record."""
    if args.no_mfa_only and record["mfa_active"] != "no":
        return False

    if args.has_keys_only and int(record["access_key_count"]) == 0:
        return False

    if args.inactive_days is not None:
        last_activity = _parse_iam_timestamp(record["last_activity"])
        if last_activity is None:
            has_active_credential = (
                record["password_enabled"] == "yes"
                or int(record["access_key_count"]) > 0
            )
            return has_active_credential
        now = datetime.now(timezone.utc)
        age_days = (now - last_activity).total_seconds() / 86400
        if age_days < args.inactive_days:
            return False

    return True


def _role_trust_matches_filters(record: dict, args) -> bool:
    """Apply CLI filters to a role-trust record."""
    if args.external_only and record["is_external"] != "yes":
        return False
    return True


def _append_finding(
    findings: list[dict],
    *,
    account_name: str,
    account_id: str,
    finding_type: str,
    resource_type: str,
    resource_name: str,
    severity: str,
    last_used: str,
    details: str,
    admin_related: bool = False,
) -> None:
    """Append a normalized hygiene finding."""
    findings.append(
        {
            "account_name": account_name,
            "account_id": account_id,
            "finding_type": finding_type,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "severity": severity,
            "last_used": last_used,
            "details": details,
            "admin_related": admin_related,
        }
    )


def _build_hygiene_findings(
    account_name: str,
    account_id: str,
    user_records: list[dict],
    role_records: list[dict],
    role_trust_records: list[dict],
    inactive_days: float,
) -> list[dict]:
    """Build derived IAM hygiene findings for one account."""
    findings = []
    external_trust_by_role: dict[str, list[dict]] = {}
    for trust_record in role_trust_records:
        if trust_record["is_external"] == "yes":
            external_trust_by_role.setdefault(trust_record["role_name"], []).append(
                trust_record
            )

    for record in user_records:
        has_active_credentials = (
            record["password_enabled"] == "yes" or int(record["access_key_count"]) > 0
        )
        last_used_age = _days_since(record["last_activity"])
        last_used = record["last_activity"]

        if int(record["access_key_count"]) > 0 and (
            last_used_age is None or last_used_age >= inactive_days
        ):
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="user_stale_access_keys",
                resource_type="user",
                resource_name=record["user_name"],
                severity="high",
                last_used=last_used,
                details=(
                    f"Active access keys present with no use in "
                    f"{inactive_days:.0f}+ days"
                    if last_used_age is not None
                    else "Active access keys present with no recorded use"
                ),
            )

        if record["password_enabled"] == "yes" and (
            last_used_age is None or last_used_age >= inactive_days
        ):
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="user_stale_console_password",
                resource_type="user",
                resource_name=record["user_name"],
                severity="medium",
                last_used=last_used,
                details=(
                    f"Console password enabled with no use in {inactive_days:.0f}+ days"
                    if last_used_age is not None
                    else "Console password enabled with no recorded use"
                ),
            )

        if has_active_credentials and record["mfa_active"] == "no":
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="user_no_mfa_with_credentials",
                resource_type="user",
                resource_name=record["user_name"],
                severity="high",
                last_used=last_used,
                details="User has active console or access-key credentials without MFA",
            )

        if _is_admin_equivalent(record["permission_summary"]):
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="user_admin_equivalent",
                resource_type="user",
                resource_name=record["user_name"],
                severity="high",
                last_used=last_used,
                details=(
                    "User appears admin-equivalent based on attached "
                    "policy heuristics"
                ),
                admin_related=True,
            )

        if int(record["inline_policy_count"]) > 0:
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="user_inline_policies",
                resource_type="user",
                resource_name=record["user_name"],
                severity="medium",
                last_used=last_used,
                details=f"User has {record['inline_policy_count']} inline polic(ies)",
            )

        if (
            _is_admin_equivalent(record["permission_summary"])
            and not record["permissions_boundary"]
        ):
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="user_admin_no_boundary",
                resource_type="user",
                resource_name=record["user_name"],
                severity="medium",
                last_used=last_used,
                details="Admin-equivalent user has no permissions boundary",
                admin_related=True,
            )

        suspicious_reason = _suspicious_name_reason(record["user_name"])
        if suspicious_reason:
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="user_suspicious_name",
                resource_type="user",
                resource_name=record["user_name"],
                severity="low",
                last_used=last_used,
                details=(
                    "User name suggests manual or exceptional access: "
                    f"{suspicious_reason}"
                ),
            )

    for record in role_records:
        if record["is_service_linked"]:
            continue

        last_used_age = _days_since(record["last_used"])
        last_used = record["last_used"]

        if last_used_age is None or last_used_age >= inactive_days:
            severity = (
                "medium"
                if _is_admin_equivalent(record["permission_summary"])
                else "low"
            )
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="role_stale_or_unused",
                resource_type="role",
                resource_name=record["role_name"],
                severity=severity,
                last_used=last_used,
                details=(
                    f"Role has not been used in {inactive_days:.0f}+ days"
                    if last_used_age is not None
                    else "Role has no recorded last-used timestamp"
                ),
                admin_related=_is_admin_equivalent(record["permission_summary"]),
            )

        if _is_admin_equivalent(record["permission_summary"]):
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="role_admin_equivalent",
                resource_type="role",
                resource_name=record["role_name"],
                severity="high",
                last_used=last_used,
                details=(
                    "Role appears admin-equivalent based on attached "
                    "policy heuristics"
                ),
                admin_related=True,
            )

        if int(record["inline_policy_count"]) > 0:
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="role_inline_policies",
                resource_type="role",
                resource_name=record["role_name"],
                severity="medium",
                last_used=last_used,
                details=f"Role has {record['inline_policy_count']} inline polic(ies)",
            )

        if (
            _is_admin_equivalent(record["permission_summary"])
            and not record["permissions_boundary"]
        ):
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="role_admin_no_boundary",
                resource_type="role",
                resource_name=record["role_name"],
                severity="medium",
                last_used=last_used,
                details="Admin-equivalent role has no permissions boundary",
                admin_related=True,
            )

        suspicious_reason = _suspicious_name_reason(record["role_name"])
        if suspicious_reason:
            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type="role_suspicious_name",
                resource_type="role",
                resource_name=record["role_name"],
                severity="low",
                last_used=last_used,
                details=(
                    "Role name suggests manual or exceptional access: "
                    f"{suspicious_reason}"
                ),
            )

        external_trusts = external_trust_by_role.get(record["role_name"], [])
        if external_trusts:
            highest_trust_risk = "high"
            if all(trust["trust_risk"] != "high" for trust in external_trusts):
                highest_trust_risk = "medium"
            trusted_targets = ", ".join(
                sorted({trust["trusted_principal"] for trust in external_trusts})
            )
            finding_type = "role_external_trust"
            admin_related = False
            if _is_admin_equivalent(record["permission_summary"]):
                finding_type = "role_admin_external_trust"
                admin_related = True

            _append_finding(
                findings,
                account_name=account_name,
                account_id=account_id,
                finding_type=finding_type,
                resource_type="role",
                resource_name=record["role_name"],
                severity=highest_trust_risk,
                last_used=last_used,
                details=f"Trusted by external or broad principals: {trusted_targets}",
                admin_related=admin_related,
            )

    return findings


def _hygiene_matches_filters(record: dict, args) -> bool:
    """Apply CLI filters to a hygiene finding."""
    if args.admin_only and not record.get("admin_related", False):
        return False
    return True


def _print_summary_record(summary_record: dict) -> None:
    """Print account-level IAM summary information."""
    print("  IAM Summary:")
    print(
        f"    Users: {summary_record['users']}  "
        f"Groups: {summary_record['groups']}  "
        f"Roles: {summary_record['roles']}  "
        f"Policies: {summary_record['policies']}"
    )
    print(
        f"    MFA devices in use: {summary_record['mfa_devices_in_use']}  "
        f"Account MFA enabled: {summary_record['account_mfa_enabled']}"
    )
    print(
        f"    Account password present: {summary_record['account_password_present']}  "
        f"Account access keys present: "
        f"{summary_record['account_access_keys_present']}  "
        f"Providers: {summary_record['providers']}"
    )


def _print_user_records(
    filtered_records: list[dict], all_records: list[dict], args
) -> None:
    """Print per-user IAM inventory or summary counts."""
    print("  IAM Users:")

    if args.summary_only:
        no_mfa_count = sum(
            1 for record in filtered_records if record["mfa_active"] == "no"
        )
        with_keys_count = sum(
            1 for record in filtered_records if int(record["access_key_count"]) > 0
        )
        admin_like_count = sum(
            1
            for record in filtered_records
            if record["permission_summary"] == "admin-equivalent"
        )
        print(f"    Matched users: {len(filtered_records)} / {len(all_records)}")
        print(f"    Without MFA: {no_mfa_count}")
        print(f"    With access keys: {with_keys_count}")
        print(f"    Admin-equivalent: {admin_like_count}")
        return

    if not filtered_records:
        print("    (no matching users)")
        return

    for record in filtered_records:
        print(
            f"    {record['user_name']:30} "
            f"keys:{record['access_key_count']:<2} "
            f"mfa:{record['mfa_active']:3} "
            f"last:{record['last_activity']:10} "
            f"perm:{record['permission_summary']}"
        )
        if record["groups"]:
            print(f"      Groups: {record['groups']}")
        if record["attached_policies"]:
            print(f"      Attached policies: {record['attached_policies']}")
        if record["permissions_boundary"]:
            print(f"      Permissions boundary: {record['permissions_boundary']}")


def _print_role_trust_records(
    filtered_records: list[dict], all_records: list[dict], args
) -> None:
    """Print role-trust findings or summary counts."""
    print("  IAM Role Trust:")

    if args.summary_only:
        high_risk = sum(
            1 for record in filtered_records if record["trust_risk"] == "high"
        )
        cross_account = sum(
            1 for record in filtered_records if record["trust_scope"] == "cross-account"
        )
        wildcard = sum(
            1 for record in filtered_records if record["trust_scope"] == "wildcard"
        )
        print(
            f"    Matched trust relationships: "
            f"{len(filtered_records)} / {len(all_records)}"
        )
        print(f"    High risk: {high_risk}")
        print(f"    Cross-account: {cross_account}")
        print(f"    Wildcard: {wildcard}")
        return

    if not filtered_records:
        print("    (no matching trust relationships)")
        return

    for record in filtered_records:
        account_ref = (
            f" account:{record['trusted_account_id']}"
            if record["trusted_account_id"]
            else ""
        )
        print(
            f"    {record['role_name']:30} "
            f"scope:{record['trust_scope']:14} "
            f"risk:{record['trust_risk']:6} "
            f"last:{record['last_used']:10}"
        )
        print(
            f"      {record['trusted_principal_type']}: "
            f"{record['trusted_principal']}{account_ref}"
        )
        if record["notes"]:
            print(f"      Notes: {record['notes']}")


def _print_hygiene_records(
    filtered_records: list[dict], all_records: list[dict], args
) -> None:
    """Print IAM hygiene findings or summary counts."""
    print("  IAM Hygiene:")

    if args.summary_only:
        severity_counts = {
            "high": sum(
                1 for record in filtered_records if record["severity"] == "high"
            ),
            "medium": sum(
                1 for record in filtered_records if record["severity"] == "medium"
            ),
            "low": sum(1 for record in filtered_records if record["severity"] == "low"),
        }
        print(f"    Matched findings: {len(filtered_records)} / {len(all_records)}")
        print(
            f"    High: {severity_counts['high']}  "
            f"Medium: {severity_counts['medium']}  "
            f"Low: {severity_counts['low']}"
        )
        return

    if not filtered_records:
        print("    (no matching hygiene findings)")
        return

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    sorted_records = sorted(
        filtered_records,
        key=lambda record: (
            severity_rank.get(record["severity"], 3),
            record["resource_type"],
            record["resource_name"].lower(),
            record["finding_type"],
        ),
    )

    for record in sorted_records:
        print(
            f"    {record['resource_type']:5} {record['resource_name']:30} "
            f"severity:{record['severity']:6} "
            f"last:{record['last_used']:10} "
            f"{record['finding_type']}"
        )
        print(f"      {record['details']}")


def enumerate_iam(args):
    """Enumerate IAM account summary and users across AWS SSO accounts."""
    from .accounts import ROLE_NAME, get_enumerable_accounts, get_role_credentials
    from .auth import get_access_token, get_sso_profile
    from .client import get_client_with_credentials, set_sso_region

    show_summary = args.summary
    show_users = args.users
    show_role_trust = args.role_trust
    show_hygiene = args.hygiene
    if not show_summary and not show_users and not show_role_trust and not show_hygiene:
        show_summary = True

    selected_reports = [
        report
        for report, enabled in (
            ("summary", show_summary),
            ("users", show_users),
            ("role_trust", show_role_trust),
            ("hygiene", show_hygiene),
        )
        if enabled
    ]

    if args.csv and len(selected_reports) > 1:
        print("ERROR: --csv supports a single IAM report at a time.")
        print(
            "Use one of --summary, --users, --role-trust, "
            "or --hygiene when exporting CSV."
        )
        return

    profile = get_sso_profile()
    access_token, sso_region = get_access_token(profile)
    set_sso_region(sso_region)

    print("SSO token valid. Enumerating IAM resources...\n")

    account_filter = None
    if args.accounts:
        account_filter = set(
            item.strip().lower() for item in args.accounts.split(",") if item.strip()
        )

    enumerable_accounts = get_enumerable_accounts(access_token)

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
                    f"  {account.get('accountName', 'Unknown')} "
                    f"({account['accountId']})"
                )
            return

        enumerable_accounts = filtered_accounts
        print(f"Filtering to {len(enumerable_accounts)} account(s): {args.accounts}\n")

    csv_file = None
    csv_writer = None
    try:
        if args.csv:
            fieldnames = SUMMARY_CSV_COLUMNS
            if show_users:
                fieldnames = USER_CSV_COLUMNS
            elif show_role_trust:
                fieldnames = ROLE_TRUST_CSV_COLUMNS
            elif show_hygiene:
                fieldnames = HYGIENE_CSV_COLUMNS
            csv_file = open(args.csv, "w", newline="")
            csv_writer = csv.DictWriter(
                csv_file, fieldnames=fieldnames, extrasaction="ignore"
            )
            csv_writer.writeheader()

        for account, roles, is_master in enumerable_accounts:
            account_id = account["accountId"]
            account_name = account.get("accountName", "Unknown")

            print(f"=== {account_name} ({account_id}) ===")

            if ROLE_NAME not in roles:
                print(f"  ERROR: {ROLE_NAME} role not provisioned. Skipping.")
                print(f"  Available roles: {', '.join(roles)}")
                print()
                continue

            credentials = get_role_credentials(account_id, ROLE_NAME, access_token)
            if not credentials:
                print(f"  ERROR: Failed to get credentials for {ROLE_NAME}")
                print()
                continue

            iam_client = get_client_with_credentials("iam", credentials)
            found_results = False
            user_records = None
            role_trust_records = None
            role_inventory_records = None

            if show_summary:
                try:
                    summary_record = _get_account_summary_record(
                        account_name, account_id, iam_client
                    )
                    _print_summary_record(summary_record)
                    if csv_writer:
                        csv_writer.writerow(summary_record)
                    found_results = True
                except Exception as exc:
                    print(f"  ERROR: Failed to retrieve IAM summary: {exc}")

            if show_users:
                try:
                    if user_records is None:
                        user_records = _build_user_records(
                            account_name, account_id, iam_client
                        )
                    all_records = user_records
                    filtered_records = [
                        record
                        for record in all_records
                        if _user_matches_filters(record, args)
                    ]
                    _print_user_records(filtered_records, all_records, args)
                    if csv_writer:
                        for record in filtered_records:
                            csv_writer.writerow(record)
                    if filtered_records or (args.summary_only and all_records):
                        found_results = True
                except Exception as exc:
                    print(f"  ERROR: Failed to retrieve IAM users: {exc}")

            if show_role_trust:
                try:
                    if role_trust_records is None:
                        role_trust_records = _build_role_trust_records(
                            account_name,
                            account_id,
                            iam_client,
                            org_id=args.org_id,
                        )
                    all_records = role_trust_records
                    filtered_records = [
                        record
                        for record in all_records
                        if _role_trust_matches_filters(record, args)
                    ]
                    _print_role_trust_records(filtered_records, all_records, args)
                    if csv_writer:
                        for record in filtered_records:
                            csv_writer.writerow(record)
                    if filtered_records or (args.summary_only and all_records):
                        found_results = True
                except Exception as exc:
                    print(f"  ERROR: Failed to retrieve IAM role trust: {exc}")

            if show_hygiene:
                try:
                    if user_records is None:
                        user_records = _build_user_records(
                            account_name, account_id, iam_client
                        )
                    if role_inventory_records is None:
                        role_inventory_records = _build_role_inventory_records(
                            account_name, account_id, iam_client
                        )
                    if role_trust_records is None:
                        role_trust_records = _build_role_trust_records(
                            account_name,
                            account_id,
                            iam_client,
                            org_id=args.org_id,
                        )
                    all_records = _build_hygiene_findings(
                        account_name,
                        account_id,
                        user_records,
                        role_inventory_records,
                        role_trust_records,
                        _default_inactive_days(args),
                    )
                    filtered_records = [
                        record
                        for record in all_records
                        if _hygiene_matches_filters(record, args)
                    ]
                    _print_hygiene_records(filtered_records, all_records, args)
                    if csv_writer:
                        for record in filtered_records:
                            csv_writer.writerow(record)
                    if filtered_records or (args.summary_only and all_records):
                        found_results = True
                except Exception as exc:
                    print(f"  ERROR: Failed to retrieve IAM hygiene findings: {exc}")

            print()

            if args.first_only and found_results:
                print(
                    "--first-only specified. "
                    "Stopping after first account with IAM findings."
                )
                break
    finally:
        if csv_file:
            csv_file.close()
            print(f"CSV output written to: {args.csv}")
