"""Base collector class that all vendor collectors inherit from."""

import os
import tempfile
import shutil
import logging
from abc import ABC, abstractmethod
from datetime import datetime

import git

from database import (
    upsert_vendor, upsert_rule, start_sync, complete_sync,
    update_vendor_stats, deactivate_missing_rules, get_db, transaction,
)

logger = logging.getLogger(__name__)

CLONE_BASE = os.environ.get(
    "RULE_AGGREGATOR_CLONE_DIR",
    os.path.join(tempfile.gettempdir(), "cybersagacity-rules"),
)


class BaseCollector(ABC):
    """Base class for all rule collectors."""

    name: str = ""
    display_name: str = ""
    source_type: str = "github"
    source_url: str = ""
    description: str = ""
    logo_url: str = ""

    def __init__(self):
        self.vendor = None
        self.sync_id = None
        self.stats = {"added": 0, "updated": 0, "unchanged": 0, "removed": 0}
        self.clone_dir = os.path.join(CLONE_BASE, self.name)
        # Rule IDs upserted during the current collect; used to deactivate
        # rules that the vendor source no longer contains.
        self.seen_rule_ids = set()

    def register_vendor(self):
        self.vendor = upsert_vendor(
            self.name, self.display_name, self.source_type,
            self.source_url, self.description, self.logo_url,
        )

    def clone_or_pull(self):
        """Clone repo if not present, otherwise pull latest."""
        os.makedirs(CLONE_BASE, exist_ok=True)
        if os.path.exists(os.path.join(self.clone_dir, ".git")):
            logger.info(f"[{self.name}] Pulling latest changes...")
            repo = git.Repo(self.clone_dir)
            origin = repo.remotes.origin
            origin.pull()
            return repo
        else:
            logger.info(f"[{self.name}] Cloning {self.source_url}...")
            repo = git.Repo.clone_from(
                self.source_url, self.clone_dir, depth=1,
                single_branch=True,
            )
            return repo

    def get_head_sha(self):
        try:
            repo = git.Repo(self.clone_dir)
            return str(repo.head.commit.hexsha)
        except Exception:
            return None

    def has_changes(self):
        """Check if remote has new commits since last sync."""
        with get_db() as conn:
            vendor = conn.execute(
                "SELECT last_commit_sha FROM vendors WHERE name=?", (self.name,)
            ).fetchone()
            if not vendor or not vendor["last_commit_sha"]:
                return True
            current_sha = self.get_head_sha()
            return current_sha != vendor["last_commit_sha"]

    def save_commit_sha(self):
        sha = self.get_head_sha()
        if sha:
            with get_db() as conn:
                conn.execute(
                    "UPDATE vendors SET last_commit_sha=? WHERE name=?",
                    (sha, self.name),
                )

    def upsert(self, rule_id, title, **kwargs):
        self.seen_rule_ids.add(rule_id)
        status, db_id = upsert_rule(
            self.vendor["id"], rule_id, title, sync_id=self.sync_id, **kwargs
        )
        self.stats[status] = self.stats.get(status, 0) + 1
        return status, db_id

    def sync(self, force=False):
        """Run a full sync for this collector."""
        self.register_vendor()
        self.sync_id = start_sync(self.vendor["id"])
        logger.info(f"[{self.name}] Starting sync (id={self.sync_id})...")

        try:
            if self.source_type == "github":
                self.clone_or_pull()
                if not force and not self.has_changes():
                    logger.info(f"[{self.name}] No changes since last sync, skipping.")
                    complete_sync(self.sync_id, "success", 0, 0, 0)
                    return self.stats

            # collect_rules + deactivation run in one transaction: tens of
            # thousands of upserts commit once (fast), and a mid-sync failure
            # rolls back atomically instead of leaving partial data.
            with transaction():
                self.collect_rules()
                removed = deactivate_missing_rules(
                    self.vendor["id"], self.seen_rule_ids, self.sync_id
                )
                self.stats["removed"] = removed

            self.save_commit_sha()
            update_vendor_stats(self.vendor["id"])

            complete_sync(
                self.sync_id, "success",
                self.stats["added"], self.stats["updated"], self.stats["removed"],
            )
            logger.info(
                f"[{self.name}] Sync complete: "
                f"+{self.stats['added']} ~{self.stats['updated']} "
                f"-{self.stats['removed']} ={self.stats['unchanged']}"
            )
        except Exception as e:
            logger.error(f"[{self.name}] Sync failed: {e}", exc_info=True)
            complete_sync(self.sync_id, "failed", error_message=str(e))
            raise

        return self.stats

    @abstractmethod
    def collect_rules(self):
        """Override this to parse and upsert rules from the vendor source."""
        pass
