import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import quote

from aws_enum import iam


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return self.pages


class FakeIamClient:
    def __init__(self, roles, role_details, operation_pages=None):
        self.roles = roles
        self.role_details = role_details
        self.operation_pages = operation_pages or {}

    def get_paginator(self, operation_name):
        if operation_name == "list_roles":
            return FakePaginator([{"Roles": self.roles}])
        if operation_name in self.operation_pages:
            return FakePaginator(self.operation_pages[operation_name])
        raise AssertionError(f"Unexpected paginator request: {operation_name}")

    def get_role(self, RoleName):
        return {"Role": self.role_details[RoleName]}


class TestIamHelpers(unittest.TestCase):
    def test_decode_credential_report_parses_rows(self):
        content = (
            "user,arn,password_enabled,mfa_active,access_key_1_active\n"
            "alice,arn:aws:iam::123456789012:user/alice,TRUE,FALSE,TRUE\n"
        ).encode("utf-8")

        rows = iam._decode_credential_report(content)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["user"], "alice")
        self.assertEqual(rows[0]["mfa_active"], "FALSE")

    def test_most_recent_activity_prefers_latest_timestamp(self):
        row = {
            "password_last_used": "2024-01-01T00:00:00+00:00",
            "access_key_1_last_used_date": "2024-02-01T00:00:00+00:00",
            "access_key_2_last_used_date": "N/A",
        }

        latest = iam._most_recent_activity(row)

        self.assertEqual(latest, datetime(2024, 2, 1, 0, 0, tzinfo=timezone.utc))

    def test_decode_policy_document_handles_url_encoded_json(self):
        encoded = quote(
            '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}}'
        )

        decoded = iam._decode_policy_document(encoded)

        self.assertEqual(decoded["Version"], "2012-10-17")
        self.assertEqual(decoded["Statement"]["Principal"], "*")

    def test_classify_permission_summary_handles_common_buckets(self):
        self.assertEqual(
            iam._classify_permission_summary(["AdministratorAccess"], 0),
            "admin-equivalent",
        )
        self.assertEqual(
            iam._classify_permission_summary(["PowerUserAccess"], 0),
            "power-user",
        )
        self.assertEqual(
            iam._classify_permission_summary(["ReadOnlyAccess"], 0),
            "read-only",
        )
        self.assertEqual(
            iam._classify_permission_summary(["CustomPolicy"], 0),
            "custom/unknown",
        )

    def test_user_matches_filters_treats_never_used_active_credentials_as_inactive(
        self,
    ):
        args = SimpleNamespace(
            no_mfa_only=False,
            has_keys_only=False,
            inactive_days=90,
        )
        record = {
            "mfa_active": "yes",
            "access_key_count": 1,
            "password_enabled": "no",
            "last_activity": "never",
        }

        self.assertTrue(iam._user_matches_filters(record, args))

    def test_user_matches_filters_respects_age_threshold(self):
        args = SimpleNamespace(
            no_mfa_only=False,
            has_keys_only=False,
            inactive_days=30,
        )
        record = {
            "mfa_active": "yes",
            "access_key_count": 1,
            "password_enabled": "no",
            "last_activity": (datetime.now(timezone.utc) - timedelta(days=10))
            .date()
            .isoformat(),
        }

        self.assertFalse(iam._user_matches_filters(record, args))

    def test_build_role_trust_records_flags_cross_account_role(self):
        created = datetime(2024, 1, 1, tzinfo=timezone.utc)
        last_used = datetime(2024, 2, 1, tzinfo=timezone.utc)
        roles = [
            {
                "RoleName": "VendorAccess",
                "Arn": "arn:aws:iam::123456789012:role/VendorAccess",
                "CreateDate": created,
            }
        ]
        role_details = {
            "VendorAccess": {
                "RoleName": "VendorAccess",
                "Arn": "arn:aws:iam::123456789012:role/VendorAccess",
                "CreateDate": created,
                "RoleLastUsed": {"LastUsedDate": last_used},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Principal": {
                                "AWS": "arn:aws:iam::999999999999:root",
                            },
                        }
                    ],
                },
            }
        }

        records = iam._build_role_trust_records(
            "Prod",
            "123456789012",
            FakeIamClient(roles, role_details),
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["trust_scope"], "cross-account")
        self.assertEqual(records[0]["is_external"], "yes")
        self.assertEqual(records[0]["trust_risk"], "high")

    def test_build_role_trust_records_recognizes_org_scoped_role(self):
        created = datetime(2024, 1, 1, tzinfo=timezone.utc)
        roles = [
            {
                "RoleName": "OrgAudit",
                "Arn": "arn:aws:iam::123456789012:role/OrgAudit",
                "CreateDate": created,
            }
        ]
        role_details = {
            "OrgAudit": {
                "RoleName": "OrgAudit",
                "Arn": "arn:aws:iam::123456789012:role/OrgAudit",
                "CreateDate": created,
                "RoleLastUsed": {},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Principal": {
                                "AWS": "arn:aws:iam::210987654321:root",
                            },
                            "Condition": {
                                "StringEquals": {"aws:PrincipalOrgID": "o-abc123xyz"}
                            },
                        }
                    ],
                },
            }
        }

        records = iam._build_role_trust_records(
            "Prod",
            "123456789012",
            FakeIamClient(roles, role_details),
            org_id="o-abc123xyz",
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["trust_scope"], "same-org")
        self.assertEqual(records[0]["is_external"], "no")
        self.assertEqual(records[0]["trust_risk"], "low")

    def test_build_hygiene_findings_flags_multiple_risks(self):
        user_records = [
            {
                "user_name": "breakglass-admin",
                "password_enabled": "yes",
                "access_key_count": 1,
                "mfa_active": "no",
                "last_activity": "never",
                "permission_summary": "admin-equivalent",
                "inline_policy_count": 1,
                "permissions_boundary": "",
            }
        ]
        role_records = [
            {
                "role_name": "VendorAdminRole",
                "last_used": "never",
                "permission_summary": "admin-equivalent",
                "inline_policy_count": 1,
                "permissions_boundary": "",
                "is_service_linked": False,
            }
        ]
        role_trust_records = [
            {
                "role_name": "VendorAdminRole",
                "is_external": "yes",
                "trust_risk": "high",
                "trusted_principal": "arn:aws:iam::999999999999:root",
            }
        ]

        findings = iam._build_hygiene_findings(
            "Prod",
            "123456789012",
            user_records,
            role_records,
            role_trust_records,
            90,
        )
        finding_types = {finding["finding_type"] for finding in findings}

        self.assertIn("user_no_mfa_with_credentials", finding_types)
        self.assertIn("user_admin_equivalent", finding_types)
        self.assertIn("user_suspicious_name", finding_types)
        self.assertIn("role_admin_external_trust", finding_types)
        self.assertIn("role_stale_or_unused", finding_types)

    def test_hygiene_matches_filters_admin_only(self):
        args = SimpleNamespace(admin_only=True)

        self.assertTrue(iam._hygiene_matches_filters({"admin_related": True}, args))
        self.assertFalse(iam._hygiene_matches_filters({"admin_related": False}, args))


if __name__ == "__main__":
    unittest.main()
