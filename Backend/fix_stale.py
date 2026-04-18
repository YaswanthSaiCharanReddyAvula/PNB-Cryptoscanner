"""Clear stale running/pending scans for testssl.sh so a new scan can start."""
import pymongo

db = pymongo.MongoClient("mongodb://localhost:27017")["quantumshield"]
r = db["scans"].update_many(
    {"domain": "testssl.sh", "status": {"$in": ["running", "pending"]}},
    {"$set": {"status": "failed", "error": "Cleared stale scan for rescan"}},
)
print(f"Cleared {r.modified_count} stale scan(s) for testssl.sh")
