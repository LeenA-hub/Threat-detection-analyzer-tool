import json
from datetime import datetime

REQUIRED_FIELDS = {"timestamp", "ip", "username", "event"}

def parse_line(line):
    '''parse one JSONL line into a dict, or return if invalid.'''
    line = line.strip()  # strip() remove trailing newline and spaces
    if not line:
        return None
    try: 
        entry = json.loads(line) #converts the JSON string into a Python dictionary
    except json.JSONDecodeError: 
        return None
    
    # Check if the entry is a dictionary and contains all required fields
    if not isinstance (entry, dict) or not REQUIRED_FIELDS.issubset(entry):
        return None
    #datetime wil give the t2-t1 time difference between two timestamps, and the fromisoformat() method will convert the timestamp string into a datetime object.
    try:
        entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
    except (ValueError, TypeError):
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
                skipped += 1  #we count skipped becuase if certain amount of our lines fails to parse, then either our parser is wrong or someone is tampering with our logs. therefore it will make the count visible.
    return entries, skipped


        
#building the detection 
from collections import defaultdict
from datetime import timedelta

FAIL_THRESHOLD = 5
WINDOW = timedelta(minutes=10)

def detect_brute_force(entries):
    alerts = []
    
    # 1. group events by IP 
    by_ip = defaultdict(list)
    for e in entries:
        by_ip[e["ip"]].append(e)
        
    # 2. walk each IP's events in time order
    for ip, events in by_ip.items():
        events.sort(key=lambda e: e["timestamp"])
        failures = []
        alerted = False
        
        for e in events:
            #Drop failures that are too old to count 
            failures = [f for f in failures if e["timestamp"] - f["timestamp"] <= WINDOW]
            if e["event"] == "login_failed":
                failures.append(e)
                if len(failures) >= FAIL_THRESHOLD and not alerted:
                    alerts.append({
                        "severity": "HIGH",
                        "rule": "brute_force",
                        "ip": ip,
                        "time": e["timestamp"],
                        "detail": f"{len(failures)} failed logins within 10 minutes",
                    })
                    alerted = True

            elif e["event"] == "login_success":
                if len(failures) >= FAIL_THRESHOLD:
                    alerts.append({
                        "severity": "CRITICAL",
                        "rule": "success_after_brute_force",
                        "ip": ip,
                        "time": e["timestamp"],
                        "detail": f"{e['username']} logged in after {len(failures)} failures",
                    })
                failures = []
                alerted = False

    return alerts



if __name__ == "__main__":
    entries, skipped = load_logs("sample_logs.jsonl")
    print(f"Loaded {len(entries)} events, skipped {skipped} bad lines\n")

    for alert in detect_brute_force(entries):
        print(f"[{alert['severity']}] {alert['rule']} | {alert['ip']} | "
              f"{alert['time']} | {alert['detail']}")