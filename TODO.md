# TODO

## Route53 DNS Audit Feature

**Goal**: Detect dangling DNS records and external/third-party targets that could indicate subdomain takeover risks or shadow IT.

### Remaining Work

#### Phase 2: Cross-Reference ELBs (Detect Dangling)

Verify AWS resource CNAMEs actually exist:
- We already enumerate ELBs across all accounts
- Build a set of all known ELB DNS names
- For any CNAME -> `*.elb.amazonaws.com`, check if ELB exists
- Flag as dangling if not found

**Requires**: running ELB enumeration first, or sharing/caching discovered ELB DNS names

#### Phase 3: IP Audit

For `A` records pointing to public IPs:
- Enumerate all Elastic IPs across accounts
- Enumerate all EC2 public IPs
- Cross-reference `A` record IPs against inventory
- Flag unknown IPs as external or unowned

**Notes**:
- Elastic IPs are the most reliable ownership signal
- EC2 public IPs can be dynamic, so output should indicate confidence

---

## ECS Public-Facing Detection

**Goal**: Identify which ECS tasks are publicly accessible.

### Implementation Phases

#### Phase 1: Network Details (`--show-network`)

Add network information to task output:
- Parse `networkBindings` and `networkInterfaces` from task details
- Show private IP
- Show public IP if assigned

#### Phase 2: ELB Cross-Reference (`--show-exposure`)

Determine whether tasks are behind internet-facing load balancers:
- `ecs describe-services` -> `loadBalancers[].targetGroupArn`
- `elbv2 describe-target-health` -> target IPs/ports
- Match task private IPs to target groups
- `elbv2 describe-load-balancers` -> `Scheme`

#### Phase 3: Security Group Analysis

For directly exposed tasks:
- Resolve task ENIs
- Inspect security groups
- Report ports open to `0.0.0.0/0` or `::/0`

#### Phase 4: Indirect Exposure via AWS Edge Services

Detect internal ALBs/NLBs that are still public via:
- CloudFront origins
- API Gateway VPC links
- Global Accelerator endpoints

### Candidate CLI Options

```text
--show-network     Show task network details (private/public IPs)
--show-exposure    Cross-reference with ELBs to show public exposure
--public-only      Only show publicly exposed tasks
```

---

## IAM Audit Command Proposal

**Goal**: Add an `iam` command for cross-account IAM reporting, with terminal-friendly summaries and CSV export for triage and offline review.

### Recommended CLI Shape

Keep the current top-level CLI pattern and add a single `iam` command with report-selection flags rather than deeply nested subcommands.

Recommended usage:

```text
./aws-enum.py iam --users
./aws-enum.py iam --role-trust --external-only
./aws-enum.py iam --hygiene --inactive-days 90
./aws-enum.py iam --summary
./aws-enum.py iam --users --csv iam-users.csv
./aws-enum.py iam --role-trust --csv iam-role-trust.csv
```

Recommended report selectors:

```text
--users         IAM users inventory
--role-trust    Cross-account and suspicious trust policies
--hygiene       Stale credentials and risky IAM patterns
--summary       Account-level IAM counts and quick signals
```

Suggested shared flags:

```text
--accounts              Comma-separated account names or IDs
--csv FILE              Export flat results to CSV
--summary-only          Print only counts and key findings
--inactive-days N       Threshold for stale credential checks
--external-only         Only show external cross-account trust
--admin-only            Only show admin-equivalent principals
--no-mfa-only           Only show identities without MFA
--has-keys-only         Only show users with access keys
--first-only            Stop after first account with findings
```

### Core Reports

#### IAM Users Inventory

List users across all accounts, including:
- user name and ARN
- password enabled / console access
- access key count
- access key last used
- user last used date where available
- attached policies and group membership
- quick permission summary:
  - `AdministratorAccess`
  - power-user style broad access
  - read-only only
  - custom / unknown

Useful flags:

```text
--csv users.csv
--inactive-days 90
--no-mfa-only
--has-keys-only
```

Suggested CSV columns:

```text
account_name,account_id,user_name,user_arn,created_at,password_enabled,
password_last_used,mfa_active,access_key_1_active,access_key_1_last_used,
access_key_2_active,access_key_2_last_used,groups,attached_policies,
inline_policy_count,permissions_boundary,permission_summary
```

#### Cross-Account Role Trust Report

Find roles that may be assumable by principals outside the account or organization:
- parse trust policies for `AWS` principals not in the current account
- flag wildcard or broad trust where present
- identify trusted account IDs
- highlight missing `ExternalId` conditions for third-party style access
- show whether trust is internal org, known external account, or ambiguous

Useful flags:

```text
--csv cross-account-roles.csv
--external-only
--org-id o-xxxxxxxxxx
```

Suggested CSV columns:

```text
account_name,account_id,role_name,role_arn,trusted_principal_type,
trusted_principal,trusted_account_id,is_external,has_external_id_condition,
has_org_condition,trust_risk,notes
```

#### Access Hygiene Report

Surface suspicious or forgotten access paths:
- users with old but still-active access keys
- users with console passwords but no recent use
- users without MFA
- roles unused for long periods, where last-used data is available
- customer-managed policies granting `*` or near-admin access
- roles/users with inline policies
- service accounts or break-glass style identities by name pattern

Suggested CSV columns:

```text
account_name,account_id,finding_type,resource_type,resource_name,
severity,last_used,details
```

### Additional IAM Audit Ideas

- Account-level IAM summary:
  - count of users, groups, roles, policies, active access keys, and MFA coverage
- Credential report ingestion:
  - use IAM credential reports to capture password state, key age, and last used data consistently
- Permission boundaries report:
  - find users and roles without boundaries in accounts that appear to rely on delegation
- Federated access inventory:
  - SAML/OIDC providers and roles intended for federation
- AssumeRole reachability map:
  - export edges between trusted and trusting accounts for graphing suspicious paths
- Admin-equivalent principals report:
  - principals with `AdministratorAccess`, `iam:*`, `sts:AssumeRole` into admin roles, or similarly broad privilege

### Suggested Output Shapes

- Human-readable grouped output by account for quick terminal triage
- `--csv FILE` for flat exports
- `--summary` for high-level counts only
- `--accounts` filter to focus on suspicious environments first
- optional `--first-only` for debugging consistency with other commands

### Why This Helps

This command would make it easier to answer:
- Which old IAM users still exist, and do they still have working credentials?
- Which accounts trust other AWS accounts, especially unknown external ones?
- Which identities have broad permissions that do not fit an SSO-first model?
- Which accounts look abandoned, inconsistent, or manually managed outside the current SSO setup?

### AWS APIs and Data Sources

#### Shared IAM Enumeration

- `iam.list_users`
- `iam.list_roles`
- `iam.list_groups`
- `iam.list_policies` for customer-managed policy inventory
- `iam.get_account_summary` for high-level counts

#### User and Credential Data

- `iam.generate_credential_report`
- `iam.get_credential_report`
- `iam.list_access_keys`
- `iam.get_access_key_last_used`
- `iam.list_mfa_devices`
- `iam.list_attached_user_policies`
- `iam.list_user_policies`
- `iam.list_groups_for_user`
- `iam.get_user`

Notes:
- The credential report should be the primary source for password enabled, password last used, access key age, and MFA presence.
- `get_access_key_last_used` is useful for fresh per-key enrichment when the credential report is incomplete or stale.

#### Role Trust and Privilege Data

- `iam.get_role`
- `iam.list_attached_role_policies`
- `iam.list_role_policies`
- `iam.get_policy`
- `iam.get_policy_version`
- `iam.get_service_last_accessed_details` only if we later choose to enrich with Access Advisor style data

Notes:
- Trust analysis comes from the role's `AssumeRolePolicyDocument`.
- Permission summaries can start with heuristic classification of attached policy names and inline policy statements.

### Detection Heuristics

#### Permission Summary

Classify users and roles into rough buckets for reporting:
- admin-equivalent: `AdministratorAccess`, wildcard `Action` with broad `Resource`, or strong IAM/STS privilege
- power-user style: broad service permissions without explicit IAM administration
- read-only: `ReadOnlyAccess` or obviously read-oriented actions
- custom/unknown: anything that needs manual review

#### Cross-Account Trust Risk

Flag higher-risk trust patterns:
- explicit trusted AWS account outside the current org
- `arn:aws:iam::*:root`
- wildcard principal
- missing `sts:ExternalId` for vendor-like trust
- no limiting conditions such as org ID, source ARN, source account, or principal tags

#### Forgotten Access Signals

Flag likely cleanup targets:
- IAM users with active keys and no recent key use
- console-enabled users with no recent password use
- users with no MFA and any active credential
- roles not used recently, where role last-used data is available
- accounts with IAM users but little evidence of SSO-first access patterns

### Current Status

Implemented:
- `iam --summary`
- `iam --users`
- `iam --role-trust`
- `iam --hygiene`

Remaining high-value work:
- admin-equivalent principal detection beyond policy-name heuristics
- permissions-boundary gap reporting
- richer stale-role prioritization using role last-used data plus trust/privilege
- broader suspicious naming-pattern and break-glass detection tuning

### Notes on Scale and Reliability

- IAM is mostly global per account, so this command should not need the `--regions` option.
- Credential report generation can take time; cache the downloaded report in memory per account during a single run.
- CSV exports should be flat and stable so they can be diffed between runs.
- Terminal output should default to concise findings, with account headers and only a few top-risk rows unless explicitly expanded later.
