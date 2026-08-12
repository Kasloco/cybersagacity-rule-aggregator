"""
CyberSagacity Rule Aggregator - Scheduled Sync
Runs monthly (or custom interval) syncs of all vendor rule sources.
Can be run as a standalone daemon or invoked via cron.
"""

import logging
import os
import signal
import sys
from datetime import datetime

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from database import init_db
from collectors import ALL_COLLECTORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("scheduler")


def run_full_sync():
    """Execute a full sync across all enabled collectors."""
    logger.info("=" * 60)
    logger.info("SCHEDULED SYNC STARTING — %s", datetime.utcnow().isoformat())
    logger.info("=" * 60)

    init_db()
    total = {"added": 0, "updated": 0, "unchanged": 0, "removed": 0, "errors": 0}

    for CollectorClass in ALL_COLLECTORS:
        c = CollectorClass()
        try:
            logger.info(f"Syncing {c.display_name}...")
            stats = c.sync(force=False)
            for k in ("added", "updated", "unchanged", "removed"):
                total[k] += stats.get(k, 0)
            logger.info(
                f"  {c.display_name}: +{stats['added']} ~{stats['updated']} "
                f"={stats['unchanged']}"
            )
        except Exception as e:
            total["errors"] += 1
            logger.error(f"  {c.display_name} FAILED: {e}")

    logger.info("=" * 60)
    logger.info(
        "SYNC COMPLETE — Added: %d | Updated: %d | Unchanged: %d | Errors: %d",
        total["added"], total["updated"], total["unchanged"], total["errors"],
    )
    logger.info("=" * 60)

    return total


def start_scheduler():
    """Start the APScheduler daemon for periodic syncs.

    Sync frequency can be configured via the SYNC_INTERVAL_HOURS env var
    (default: 168 = weekly). Monthly is also supported via SYNC_SCHEDULE=monthly.
    """
    scheduler = BlockingScheduler()

    schedule_mode = os.environ.get("SYNC_SCHEDULE", "weekly")

    if schedule_mode == "monthly":
        # Monthly sync on the 1st at 3:00 AM UTC
        scheduler.add_job(
            run_full_sync,
            CronTrigger(day=1, hour=3, minute=0),
            id="monthly_sync",
            name="Monthly Rule Sync",
            misfire_grace_time=86400,
        )
        logger.info("Monthly sync scheduled for 1st of each month at 03:00 UTC.")
    elif schedule_mode == "daily":
        # Daily sync at 3:00 AM UTC
        scheduler.add_job(
            run_full_sync,
            CronTrigger(hour=3, minute=0),
            id="daily_sync",
            name="Daily Rule Sync",
            misfire_grace_time=3600,
        )
        logger.info("Daily sync scheduled at 03:00 UTC.")
    else:
        # Weekly sync on Sundays at 3:00 AM UTC (default)
        scheduler.add_job(
            run_full_sync,
            CronTrigger(day_of_week="sun", hour=3, minute=0),
            id="weekly_sync",
            name="Weekly Rule Sync",
            misfire_grace_time=86400,
        )
        logger.info("Weekly sync scheduled for Sundays at 03:00 UTC.")

    # Also run immediately on startup
    scheduler.add_job(
        run_full_sync,
        "date",
        run_date=datetime.utcnow(),
        id="startup_sync",
        name="Startup Sync",
    )

    def shutdown(signum, frame):
        logger.info("Shutting down scheduler...")
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("CyberSagacity Rule Scheduler started.")
    logger.info("Monthly sync scheduled for 1st of each month at 03:00 UTC.")
    scheduler.start()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        init_db()
        total = run_full_sync()
        if total["errors"]:
            logger.error("One or more collectors failed — exiting non-zero.")
            sys.exit(1)
    else:
        start_scheduler()
