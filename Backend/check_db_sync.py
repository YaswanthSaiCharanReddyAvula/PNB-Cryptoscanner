from pymongo import MongoClient

def run():
    client = MongoClient('mongodb://localhost:27017')
    db = client['quantumshield']
    
    # Get all scans
    scans = list(db['scans'].find({"status": "completed"}).limit(10))
    for scan in scans:
        domain = scan.get("domain")
        cbom = scan.get("cbom_report", {})
        components = cbom.get("components", [])
        print(f"Domain: {domain}, Components: {len(components)}")

if __name__ == "__main__":
    run()
