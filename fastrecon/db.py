"""
FastRecon Database — SQLite-backed state tracking, diff engine, and data management.
Surfaces only NEW subdomains per scan cycle and persists all scan history.
"""

import sqlite3
import os
import json
from datetime import datetime, timezone, timedelta


DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "fastrecon.db")


class ScanDatabase:
    """SQLite database for state tracking and data management."""

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _connect(self):
        """Get a database connection with WAL mode for concurrency."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        """Create tables if they don't exist."""
        conn = self._connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    added_at TEXT NOT NULL,
                    last_scanned TEXT,
                    notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_domain TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    http_status INTEGER,
                    title TEXT DEFAULT '',
                    server TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    UNIQUE(target_domain, subdomain)
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    mode TEXT DEFAULT 'normal',
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    duration TEXT,
                    risk_level TEXT DEFAULT 'CLEAN',
                    risk_score INTEGER DEFAULT 0,
                    total_alerts INTEGER DEFAULT 0,
                    subdomains_found INTEGER DEFAULT 0,
                    new_subdomains INTEGER DEFAULT 0,
                    live_hosts INTEGER DEFAULT 0,
                    report_json TEXT,
                    status TEXT DEFAULT 'running'
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    type TEXT NOT NULL,
                    asset TEXT,
                    service TEXT,
                    details TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    found_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target_domain);
                CREATE INDEX IF NOT EXISTS idx_subdomains_search ON subdomains(subdomain);
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_alerts_scan ON alerts(scan_id);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            """)
            conn.commit()
        finally:
            conn.close()

    # ──────────────────────────────────────────────
    #  Target Management
    # ──────────────────────────────────────────────

    def save_target(self, domain, notes=""):
        """Save a target domain for tracking."""
        conn = self._connect()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT OR IGNORE INTO targets (domain, added_at, notes) VALUES (?, ?, ?)",
                (domain, now, notes),
            )
            conn.commit()
        finally:
            conn.close()

    def get_targets(self):
        """Get all saved targets."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM targets ORDER BY added_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def delete_target(self, target_id):
        """Delete a target and all its subdomains."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT domain FROM targets WHERE id = ?", (target_id,)).fetchone()
            if row:
                domain = row["domain"]
                conn.execute("DELETE FROM subdomains WHERE target_domain = ?", (domain,))
                conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
                conn.commit()
                return True
            return False
        finally:
            conn.close()

    def update_target_last_scanned(self, domain):
        """Update the last scanned timestamp for a target."""
        conn = self._connect()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE targets SET last_scanned = ? WHERE domain = ?",
                (now, domain),
            )
            conn.commit()
        finally:
            conn.close()

    # ──────────────────────────────────────────────
    #  Subdomain State Tracking (Diff Engine)
    # ──────────────────────────────────────────────

    def get_new_subdomains(self, target, current_subdomains):
        """
        Compare current scan results against stored subdomains.
        Returns set of NEW subdomains not seen before.
        Updates last_seen for existing ones.

        Args:
            target: Target domain
            current_subdomains: Set of subdomains from current scan

        Returns:
            set of newly discovered subdomains
        """
        conn = self._connect()
        try:
            now = datetime.now(timezone.utc).isoformat()

            # Get all previously known subdomains for this target
            rows = conn.execute(
                "SELECT subdomain FROM subdomains WHERE target_domain = ?",
                (target,),
            ).fetchall()
            known = {r["subdomain"] for r in rows}

            # Find new ones
            new_subdomains = current_subdomains - known

            # Update last_seen for all current subdomains that already exist
            existing = current_subdomains & known
            if existing:
                conn.executemany(
                    "UPDATE subdomains SET last_seen = ? WHERE target_domain = ? AND subdomain = ?",
                    [(now, target, sub) for sub in existing],
                )

            # Insert new subdomains
            if new_subdomains:
                conn.executemany(
                    """INSERT OR IGNORE INTO subdomains
                       (target_domain, subdomain, first_seen, last_seen)
                       VALUES (?, ?, ?, ?)""",
                    [(target, sub, now, now) for sub in new_subdomains],
                )

            conn.commit()
            return new_subdomains
        finally:
            conn.close()

    def update_subdomain_info(self, target, subdomain, http_status=None, title="",
                               server="", ip_address="", status="live"):
        """Update enrichment data for a subdomain after probing."""
        conn = self._connect()
        try:
            conn.execute(
                """UPDATE subdomains
                   SET status = ?, http_status = ?, title = ?, server = ?, ip_address = ?
                   WHERE target_domain = ? AND subdomain = ?""",
                (status, http_status, title, server, ip_address, target, subdomain),
            )
            conn.commit()
        finally:
            conn.close()

    def get_subdomains(self, target, search=None, limit=500, offset=0):
        """Get stored subdomains for a target with optional search."""
        conn = self._connect()
        try:
            if search:
                rows = conn.execute(
                    """SELECT * FROM subdomains
                       WHERE target_domain = ? AND subdomain LIKE ?
                       ORDER BY first_seen DESC LIMIT ? OFFSET ?""",
                    (target, f"%{search}%", limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM subdomains
                       WHERE target_domain = ?
                       ORDER BY first_seen DESC LIMIT ? OFFSET ?""",
                    (target, limit, offset),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def count_subdomains(self, target):
        """Count total subdomains for a target."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM subdomains WHERE target_domain = ?",
                (target,),
            ).fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    def bulk_delete_subdomains(self, subdomain_ids):
        """Delete subdomains by their IDs."""
        conn = self._connect()
        try:
            placeholders = ",".join("?" for _ in subdomain_ids)
            conn.execute(
                f"DELETE FROM subdomains WHERE id IN ({placeholders})",
                subdomain_ids,
            )
            conn.commit()
            return conn.total_changes
        finally:
            conn.close()

    # ──────────────────────────────────────────────
    #  Scan History
    # ──────────────────────────────────────────────

    def save_scan(self, scan_id, target, mode, report=None, duration="",
                  new_subdomains_count=0):
        """Save a completed scan to history."""
        conn = self._connect()
        try:
            now = datetime.now(timezone.utc).isoformat()
            stats = report.get("stats", {}) if report else {}
            report_json = json.dumps(report, ensure_ascii=False) if report else None

            conn.execute(
                """INSERT OR REPLACE INTO scans
                   (id, target, mode, started_at, completed_at, duration,
                    risk_level, risk_score, total_alerts, subdomains_found,
                    new_subdomains, live_hosts, report_json, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, target, mode, now, now, duration,
                    report.get("riskLevel", "CLEAN") if report else "CLEAN",
                    report.get("riskScore", 0) if report else 0,
                    stats.get("totalAlerts", 0),
                    stats.get("subdomainsDiscovered", 0),
                    new_subdomains_count,
                    stats.get("liveHosts", 0),
                    report_json,
                    "complete",
                ),
            )

            # Save individual alerts
            if report:
                for alert in report.get("alerts", []):
                    conn.execute(
                        """INSERT INTO alerts
                           (scan_id, target, severity, type, asset, service,
                            details, evidence, remediation, found_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            scan_id, target,
                            alert.get("severity", "INFO"),
                            alert.get("type", ""),
                            alert.get("asset", ""),
                            alert.get("service", ""),
                            alert.get("details", ""),
                            alert.get("evidence", ""),
                            alert.get("remediation", ""),
                            now,
                        ),
                    )

            conn.commit()
        finally:
            conn.close()

    def get_scans(self, target=None, limit=50, offset=0):
        """Get scan history, optionally filtered by target."""
        conn = self._connect()
        try:
            if target:
                rows = conn.execute(
                    """SELECT id, target, mode, started_at, completed_at, duration,
                              risk_level, risk_score, total_alerts, subdomains_found,
                              new_subdomains, live_hosts, status
                       FROM scans WHERE target = ?
                       ORDER BY started_at DESC LIMIT ? OFFSET ?""",
                    (target, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, target, mode, started_at, completed_at, duration,
                              risk_level, risk_score, total_alerts, subdomains_found,
                              new_subdomains, live_hosts, status
                       FROM scans
                       ORDER BY started_at DESC LIMIT ? OFFSET ?""",
                    (limit, offset),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_scan_report(self, scan_id):
        """Get the full JSON report for a scan."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT report_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if row and row["report_json"]:
                return json.loads(row["report_json"])
            return None
        finally:
            conn.close()

    def delete_scan(self, scan_id):
        """Delete a scan and its alerts."""
        conn = self._connect()
        try:
            conn.execute("DELETE FROM alerts WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def purge_old_scans(self, days=30):
        """Delete scans older than N days."""
        conn = self._connect()
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            # Get scan IDs to delete
            rows = conn.execute(
                "SELECT id FROM scans WHERE started_at < ?", (cutoff,)
            ).fetchall()
            scan_ids = [r["id"] for r in rows]

            if scan_ids:
                placeholders = ",".join("?" for _ in scan_ids)
                conn.execute(f"DELETE FROM alerts WHERE scan_id IN ({placeholders})", scan_ids)
                conn.execute(f"DELETE FROM scans WHERE id IN ({placeholders})", scan_ids)
                conn.commit()

            return len(scan_ids)
        finally:
            conn.close()

    def get_scan_stats(self):
        """Get aggregate statistics across all scans."""
        conn = self._connect()
        try:
            stats = {}
            row = conn.execute("SELECT COUNT(*) as cnt FROM scans").fetchone()
            stats["total_scans"] = row["cnt"] if row else 0

            row = conn.execute("SELECT COUNT(DISTINCT target) as cnt FROM scans").fetchone()
            stats["unique_targets"] = row["cnt"] if row else 0

            row = conn.execute("SELECT COUNT(*) as cnt FROM subdomains").fetchone()
            stats["total_subdomains"] = row["cnt"] if row else 0

            row = conn.execute("SELECT COUNT(*) as cnt FROM alerts").fetchone()
            stats["total_alerts"] = row["cnt"] if row else 0

            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'CRITICAL'"
            ).fetchone()
            stats["critical_alerts"] = row["cnt"] if row else 0

            return stats
        finally:
            conn.close()
