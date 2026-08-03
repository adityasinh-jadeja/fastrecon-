"""
Tests for fastrecon.db — ScanDatabase CRUD operations, diff engine,
scan history, and data management.
"""

import os
import tempfile
import json
import pytest
from datetime import datetime, timezone, timedelta

from fastrecon.db import ScanDatabase


@pytest.fixture
def db():
    """Create a temporary database for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = ScanDatabase(db_path=path)
    yield database
    os.remove(path)


# ──────────────────────────────────────────────
#  Target Management
# ──────────────────────────────────────────────

class TestTargetManagement:
    def test_save_and_get_target(self, db):
        db.save_target("example.com", notes="test target")
        targets = db.get_targets()
        assert len(targets) == 1
        assert targets[0]["domain"] == "example.com"
        assert targets[0]["notes"] == "test target"

    def test_save_duplicate_target_ignored(self, db):
        db.save_target("example.com")
        db.save_target("example.com")  # should be ignored (INSERT OR IGNORE)
        targets = db.get_targets()
        assert len(targets) == 1

    def test_delete_target(self, db):
        db.save_target("example.com")
        target_id = db.get_targets()[0]["id"]
        assert db.delete_target(target_id) is True
        assert db.get_targets() == []

    def test_delete_nonexistent_target(self, db):
        assert db.delete_target(9999) is False

    def test_delete_target_cascades_subdomains(self, db):
        db.save_target("example.com")
        # Manually insert a subdomain linked to this target
        db.get_new_subdomains("example.com", {"sub.example.com"})
        assert db.count_subdomains("example.com") == 1

        target_id = db.get_targets()[0]["id"]
        db.delete_target(target_id)
        assert db.count_subdomains("example.com") == 0


# ──────────────────────────────────────────────
#  Subdomain Diff Engine
# ──────────────────────────────────────────────

class TestSubdomainDiffEngine:
    def test_first_scan_all_new(self, db):
        subs = {"a.example.com", "b.example.com", "c.example.com"}
        new = db.get_new_subdomains("example.com", subs)
        assert new == subs

    def test_second_scan_only_new_returned(self, db):
        first = {"a.example.com", "b.example.com"}
        db.get_new_subdomains("example.com", first)

        second = {"a.example.com", "b.example.com", "c.example.com"}
        new = db.get_new_subdomains("example.com", second)
        assert new == {"c.example.com"}

    def test_no_new_subdomains(self, db):
        subs = {"a.example.com"}
        db.get_new_subdomains("example.com", subs)
        new = db.get_new_subdomains("example.com", subs)
        assert new == set()

    def test_get_subdomains_returns_stored(self, db):
        db.get_new_subdomains("example.com", {"sub1.example.com", "sub2.example.com"})
        stored = db.get_subdomains("example.com")
        domains = {s["subdomain"] for s in stored}
        assert domains == {"sub1.example.com", "sub2.example.com"}

    def test_count_subdomains(self, db):
        db.get_new_subdomains("example.com", {"a.example.com", "b.example.com"})
        assert db.count_subdomains("example.com") == 2
        assert db.count_subdomains("other.com") == 0


# ──────────────────────────────────────────────
#  Scan History
# ──────────────────────────────────────────────

class TestScanHistory:
    def _make_report(self, target="example.com"):
        return {
            "target": target,
            "riskLevel": "MEDIUM",
            "riskScore": 45,
            "stats": {
                "totalAlerts": 3,
                "subdomainsDiscovered": 10,
                "liveHosts": 5,
            },
            "alerts": [],
        }

    def test_save_and_retrieve_scan(self, db):
        report = self._make_report()
        db.save_scan("scan_001", "example.com", "normal", report=report, duration="12.5s")

        scans = db.get_scans()
        assert len(scans) == 1
        assert scans[0]["target"] == "example.com"
        assert scans[0]["risk_level"] == "MEDIUM"

    def test_get_scan_report_json(self, db):
        report = self._make_report()
        db.save_scan("scan_001", "example.com", "normal", report=report)

        retrieved = db.get_scan_report("scan_001")
        assert retrieved is not None
        assert retrieved["target"] == "example.com"
        assert retrieved["riskScore"] == 45

    def test_get_nonexistent_scan_report(self, db):
        assert db.get_scan_report("nonexistent") is None

    def test_delete_scan(self, db):
        report = self._make_report()
        db.save_scan("scan_001", "example.com", "normal", report=report)
        db.delete_scan("scan_001")
        assert db.get_scans() == []

    def test_purge_old_scans(self, db):
        report = self._make_report()
        db.save_scan("scan_old", "example.com", "normal", report=report)

        # Manually backdate the scan
        conn = db._connect()
        old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        conn.execute("UPDATE scans SET started_at = ? WHERE id = ?", (old_date, "scan_old"))
        conn.commit()
        conn.close()

        purged = db.purge_old_scans(days=30)
        assert purged == 1
        assert db.get_scans() == []

    def test_get_scan_stats(self, db):
        stats = db.get_scan_stats()
        assert stats["total_scans"] == 0
        assert stats["total_subdomains"] == 0

        report = self._make_report()
        db.save_scan("scan_001", "example.com", "normal", report=report)
        db.get_new_subdomains("example.com", {"a.example.com"})

        stats = db.get_scan_stats()
        assert stats["total_scans"] == 1
        assert stats["total_subdomains"] == 1

    def test_filter_scans_by_target(self, db):
        db.save_scan("s1", "a.com", "normal", report=self._make_report("a.com"))
        db.save_scan("s2", "b.com", "normal", report=self._make_report("b.com"))

        scans = db.get_scans(target="a.com")
        assert len(scans) == 1
        assert scans[0]["target"] == "a.com"
