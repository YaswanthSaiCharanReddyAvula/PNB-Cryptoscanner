"""Clear stale running/pending scans so a new scan can start."""
import pymongo

db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["quantumshield"]
r = db["scans"].update_many(
    {"status": {"$in": ["running", "pending"]}},
    {"$set": {"status": "failed", "error": "Cleared stale scan for rescan"}},
)
print(f"Cleared {r.modified_count} stale scan(s)")
