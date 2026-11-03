import json
from datetime import datetime

REQUIRED_FIELDS = ["timestamp", "ip", "username", "event"}

def parse_line(line):
    '''parse one JSONL line into a dict, or return if invalid.'''
    line = line.strip()
    if not line:
        return None
    try: 
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None
    
    if not isinstance (entry, dict) or not REQUIRED_FIELDS.issubset(entry):
        return None
    
    try:
        entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
    except ValueError:
        return None
    
    return entry

def load_logs(path):
    entries = []
    skipped = 0
    with open(path) as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                entries.append(parsed)
            else:
                skipped += 1
    return entries, skipped

if __name__ == "__main__":
    entries, skipped = load_logs("sample.jsonl")
    print(f"Loaded {len(entries)} events, skipped {skipped} bad lines")
    for e in entries[:3]:
        print(e)