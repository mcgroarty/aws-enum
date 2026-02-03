import unittest
from datetime import datetime, timezone, timedelta

from aws_enum import ecs


class TestEcsParsing(unittest.TestCase):
    def test_parse_started_at_accepts_datetime(self):
        started = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        parsed = ecs._parse_started_at(started)
        self.assertEqual(parsed, started)

    def test_parse_started_at_accepts_naive_datetime(self):
        started = datetime(2024, 1, 1, 12, 0, 0)
        parsed = ecs._parse_started_at(started)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_parse_started_at_accepts_string(self):
        parsed = ecs._parse_started_at("2024-01-01T12:00:00Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_parse_started_at_invalid_returns_none(self):
        self.assertIsNone(ecs._parse_started_at("not-a-date"))

    def test_format_age_invalid_returns_unknown(self):
        self.assertEqual(ecs.format_age("not-a-date"), "unknown")

    def test_get_task_age_days_accepts_datetime(self):
        started = datetime.now(timezone.utc) - timedelta(hours=1)
        age_days = ecs.get_task_age_days(started)
        self.assertIsInstance(age_days, float)
        self.assertGreaterEqual(age_days, 0.0)


if __name__ == "__main__":
    unittest.main()
