"""
Phase 2.1 Live Verification Script
Runs 5 consecutive scans and reports events generated at each step.
Verifies the debounce layer works correctly with real Wi-Fi scan data.
"""
import time
from scanner.scanner_manager import ScannerManager
from utils.parser import parse_networks
from storage.database import DatabaseManager
from monitoring.change_detector import detect_changes
from monitoring.event_manager import EventManager
from datetime import datetime

# Use a temporary database to avoid polluting production data
db = DatabaseManager("data/wifi_scanner_test.db")
db.clear_history()
event_mgr = EventManager(db)
scanner = ScannerManager()

print("=" * 60)
print("Phase 2.1 Live Debounce Verification")
print("=" * 60)
print(f"Missing threshold: 3 consecutive scans\n")

total_events = 0

for i in range(1, 6):
    start = time.time()
    raw = scanner.scan()
    nets = parse_networks(raw)
    duration = time.time() - start
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scan_id, prev_states = db.save_scan(nets, duration)
    events = detect_changes(prev_states, nets, ts)
    count = event_mgr.record_events(events)
    total_events += count

    stats = db.get_monitoring_stats()

    print(f"--- Scan {i} (ID: {scan_id}) ---")
    print(f"  Networks found: {len(nets)}")
    print(f"  Previous tracked: {len(prev_states)}")
    print(f"  Events this scan: {count}")
    for ev in events:
        print(f"    -> {ev['event_type']} ({ev['severity']}): {ev['bssid']} {ev.get('ssid','')}")
    print(f"  DB Stats: tracked={stats['tracked_bssids']} active={stats['active_bssids']} "
          f"new_bssids={stats['new_networks_count']} confirmed_missing={stats['not_detected_count']}")
    print()

    if i < 5:
        time.sleep(2)

print("=" * 60)
print(f"Total events across 5 scans: {total_events}")
final_stats = db.get_monitoring_stats()
print(f"Final: scans={final_stats['total_scans']} tracked={final_stats['tracked_bssids']} "
      f"active={final_stats['active_bssids']} new={final_stats['new_networks_count']} "
      f"missing={final_stats['not_detected_count']} high={final_stats['high_severity_events']}")
print("=" * 60)

# Cleanup test database
import os
try:
    del db
    os.remove("data/wifi_scanner_test.db")
    print("\nTest database cleaned up.")
except Exception:
    pass
