# This module handles exporting simulated reconnaissance events
# into JSON or CSV formats. These exports can be used for:
# - SIEM ingestion
# - log analysis testing
# - correlation pipelines
# - demo datasets

import json
import csv

# Export events to a JSON file
def export_json(events, filename):
    with open(filename, "w") as f:
        json.dump(events, f, indent=4)

# Export events to a CSV file
def export_csv(events, filename):
    keys = events[0].keys()
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(events)
