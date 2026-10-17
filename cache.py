import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from models import IOC

load_dotenv()

CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))


def _has_error(result):
    return isinstance(result, dict) and "error" in result


def _is_usable(row):
    results = [r for r in (row.virustotal_result, row.abuseipdb_result) if r is not None]
    return len(results) > 0 and not any(_has_error(r) for r in results)


def find_cached(db, ioc: str, ioc_type: str):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CACHE_TTL_HOURS)

    rows = (
        db.query(IOC)
        .filter(IOC.ioc == ioc, IOC.type == ioc_type, IOC.created_at >= cutoff)
        .order_by(IOC.created_at.desc())
        .all()
    )

    for row in rows:
        if _is_usable(row):
            return row
    return None