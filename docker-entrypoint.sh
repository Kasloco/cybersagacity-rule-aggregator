#!/bin/sh
set -e

# Sync rules from all vendors on first start so a fresh deployment is not
# empty. Disable with RULE_AGGREGATOR_SYNC_ON_START=0. The rules database and
# git clones live on a persistent volume, so restarts skip the work via the
# vendor last_commit_sha check in BaseCollector.has_changes().
if [ "${RULE_AGGREGATOR_SYNC_ON_START:-1}" = "1" ]; then
    echo "[entrypoint] Running initial sync..."
    python scheduler.py --once
fi

exec gunicorn --bind 0.0.0.0:8080 --workers 2 --timeout 120 app:app
