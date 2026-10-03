"""
QuantumShield — CVE Database Synchronizer

Provides a mechanism to update the local cve_cache.json from external feeds
(e.g., NVD, OSV) via scheduled tasks or manual triggers.
"""

import json
from pathlib import Path
from datetime import datetime
from app.utils.logger import get_logger

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_CACHE_FILE = _DATA_DIR / "cve_cache.json"

class CVESyncManager:
    @staticmethod
    def sync_from_feed(feed_data: list[dict], source_name: str = "NVD") -> bool:
        """
        Validates and atomically replaces the local CVE cache with new feed data.
        """
        validated_records = []
        for record in feed_data:
            # Validate required fields
            if not record.get("cve_id") or not record.get("cpe_prefix"):
                continue
            
            # Normalize version ranges
            if "affected_versions" in record and "affected_ranges" not in record:
                record["affected_ranges"] = record["affected_versions"]
            
            validated_records.append(record)

        if not validated_records:
            logger.error("CVE Sync failed: Feed contained no valid records.")
            return False

        cache_obj = {
            "_metadata": {
                "source": source_name,
                "last_updated": datetime.utcnow().isoformat() + "Z",
                "schema_version": "1.0",
                "record_count": len(validated_records)
            },
            "records": validated_records
        }

        # Atomic replacement
        tmp_path = _CACHE_FILE.with_suffix(".tmp")
        try:
            tmp_path.write_text(json.dumps(cache_obj, indent=2), encoding="utf-8")
            tmp_path.replace(_CACHE_FILE)
            logger.info(f"CVE cache updated successfully. Records: {len(validated_records)}")
            return True
        except Exception as e:
            logger.error(f"Failed to write CVE cache: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            return False

    @staticmethod
    def get_cache_status() -> dict:
        """Returns the freshness and status of the current cache."""
        if not _CACHE_FILE.exists():
            return {"status": "MISSING", "last_updated": None, "record_count": 0}
        
        try:
            data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
            meta = data.get("_metadata", {})
            return {
                "status": "FRESH" if meta else "LEGACY",
                "last_updated": meta.get("last_updated"),
                "record_count": meta.get("record_count", len(data) if isinstance(data, list) else 0)
            }
        except Exception:
            return {"status": "CORRUPTED", "last_updated": None, "record_count": 0}
