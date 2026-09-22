"""
TraceX - Event Timeline Forensics Engine

Version 2.0
Pure Python + Matplotlib

No AI / No Machine Learning / No External Database
Deterministic Rule-Based Forensic Log Analysis
"""

import csv
import json
import os
import sys
from datetime import datetime, timezone
import matplotlib.pyplot as plt


# ============================================================
# 1. CONFIGURATION
# ============================================================

# Actions recognized by TraceX
KNOWN_ACTIONS = {
    "login",
    "logout",
    "order_created",
    "read",
    "delete",
    "upload",
    "download",
    "payment",
    "password_reset",
    "permission_change",
}

# Prerequisites: action -> list of required prerequisite actions
# Each prerequisite must have occurred within the active session
SESSION_RULES = {
    "read": ["login"],
    "delete": ["login"],
    "upload": ["login"],
    "download": ["login"],
    "payment": ["order_created"],
}

# Actions that strictly require an active login session
SESSION_REQUIRED_ACTIONS = {
    "read",
    "delete",
    "upload",
    "download",
    "payment",
    "permission_change",
}

# Maximum allowed idle time before a session is considered expired (in seconds)
# Set to None to disable session timeout checks
SESSION_TIMEOUT_SECONDS = 3600  # 1 hour

# Maximum allowed time window between prerequisite and subsequent action (in seconds)
# E.g. payment must occur within 30 minutes (1800s) of order_created
PREREQUISITE_TIME_WINDOWS = {
    ("payment", "order_created"): 1800,  # 30 minutes
}

# Threshold (in seconds) below which two distinct user actions are flagged as rapid burst/bot activity
RAPID_BURST_THRESHOLD = 0.05


# ============================================================
# 2. SAMPLE DATA
# ============================================================

SAMPLE_EVENTS = [
    {
        "time": 1,
        "user": "ali",
        "action": "login",
    },
    {
        "time": 2,
        "user": "ali",
        "action": "read",
    },
    {
        "time": 3,
        "user": "ali",
        "action": "order_created",
    },
    {
        "time": 4,
        "user": "ali",
        "action": "payment",
    },
    {
        "time": 5,
        "user": "ali",
        "action": "delete",
    },
    {
        "time": 6,
        "user": "ali",
        "action": "logout",
    },
    {
        # Invalid: read after logout (ACTION_WHILE_LOGGED_OUT)
        "time": 7,
        "user": "ali",
        "action": "read",
    },
    {
        # Valid login to re-establish session
        "time": 8,
        "user": "ali",
        "action": "login",
    },
    {
        # Invalid: duplicate login without logout
        "time": 9,
        "user": "ali",
        "action": "login",
    },
    {
        # Invalid: unknown action
        "time": 10,
        "user": "ali",
        "action": "hack",
    },
    {
        # Invalid: logout while already logged out
        "time": 11,
        "user": "sara",
        "action": "logout",
    },
    {
        # Sara logs in
        "time": 12,
        "user": "sara",
        "action": "login",
    },
    {
        # Invalid: payment without order_created in active session
        "time": 13,
        "user": "sara",
        "action": "payment",
    },
]


# ============================================================
# 3. TIME PARSING & NORMALIZATION
# ============================================================

def parse_event_time(raw_time):
    """
    Parse event time into a standardized numeric epoch (float/int)
    and a human-readable display string.

    Supports:
        - Integers / Floats (e.g. 1, 100.5, 1711111111)
        - ISO-8601 Strings (e.g. '2026-09-22T14:30:00Z', '2026-09-22 14:30:00')
    
    Returns:
        (is_valid, numeric_epoch, display_string)
    """
    if isinstance(raw_time, (int, float)):
        return True, float(raw_time), str(raw_time)

    if isinstance(raw_time, str):
        cleaned = raw_time.strip()
        # Try numeric string first
        try:
            val = float(cleaned)
            return True, val, cleaned
        except ValueError:
            pass

        # Try ISO-8601 parsing
        iso_formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]
        
        # Python 3.7+ fromisoformat handles standard ISO strings
        try:
            dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
            epoch = dt.timestamp()
            return True, epoch, cleaned
        except (ValueError, TypeError):
            pass

        for fmt in iso_formats:
            try:
                dt = datetime.strptime(cleaned, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return True, dt.timestamp(), cleaned
            except ValueError:
                continue

    return False, None, str(raw_time)


# ============================================================
# 4. BASIC VALIDATION
# ============================================================

def validate_event(event):
    """
    Validate structure, fields, and data types of a single event dictionary.

    Returns:
        (True, "") or (False, error_message)
    """
    if not isinstance(event, dict):
        return False, "Event must be a dictionary."

    required_fields = {"time", "user", "action"}
    missing_fields = required_fields - set(event.keys())

    if missing_fields:
        return False, f"Missing fields: {', '.join(sorted(missing_fields))}"

    valid_time, _, _ = parse_event_time(event.get("time"))
    if not valid_time:
        return False, f"Time value '{event.get('time')}' is neither a valid number nor a recognizable ISO timestamp."

    if not isinstance(event["user"], str) or not event["user"].strip():
        return False, "User must be a non-empty string."

    if not isinstance(event["action"], str) or not event["action"].strip():
        return False, "Action must be a non-empty string."

    return True, ""


def validate_events(events):
    """
    Validate an entire list of events.

    Returns:
        list of problem dictionaries with index and error message
    """
    problems = []

    if not isinstance(events, list):
        return [{"index": -1, "error": "Input data must be a list."}]

    for index, event in enumerate(events):
        valid, error = validate_event(event)
        if not valid:
            problems.append({
                "index": index,
                "error": error,
            })

    return problems


# ============================================================
# 5. SORTING & TIMELINE
# ============================================================

def get_event_numeric_time(event):
    """Extract numeric epoch time from event for sorting and math."""
    valid, num_time, _ = parse_event_time(event.get("time"))
    return num_time if valid and num_time is not None else float("inf")


def sort_events(events):
    """Return a new list of events sorted chronologically by time."""
    return sorted(events, key=get_event_numeric_time)


def detect_time_order_anomalies(events):
    """
    Detect events whose timestamp goes backwards in the original dataset order.
    In forensic investigations, inverted log order can indicate log tampering.
    """
    anomalies = []

    for i in range(1, len(events)):
        prev_valid, prev_epoch, prev_disp = parse_event_time(events[i - 1].get("time"))
        curr_valid, curr_epoch, curr_disp = parse_event_time(events[i].get("time"))

        if prev_valid and curr_valid and curr_epoch < prev_epoch:
            anomalies.append({
                "type": "TIME_ORDER",
                "time": events[i].get("time"),
                "user": events[i].get("user", "UNKNOWN"),
                "action": events[i].get("action", "UNKNOWN"),
                "severity": "HIGH",
                "reason": (
                    f"Timestamp '{curr_disp}' appears chronologically before "
                    f"previous event timestamp '{prev_disp}'. Potential log tampering or clock skew."
                ),
            })

    return anomalies


# ============================================================
# 6. SEVERITY ASSIGNMENT
# ============================================================

def calculate_severity(anomaly_type):
    """Return standard severity level for a given anomaly type."""
    severity_map = {
        "MALFORMED_EVENT": "HIGH",
        "MISSING_FIELD": "HIGH",
        "UNKNOWN_ACTION": "MEDIUM",
        "TIME_ORDER": "HIGH",
        "ACTION_WHILE_LOGGED_OUT": "HIGH",
        "DUPLICATE_LOGIN": "MEDIUM",
        "LOGOUT_WITHOUT_LOGIN": "LOW",
        "MISSING_PREREQUISITE": "HIGH",
        "PREREQUISITE_TIMEOUT": "MEDIUM",
        "SESSION_EXPIRED": "MEDIUM",
        "RAPID_BURST": "LOW",
    }
    return severity_map.get(anomaly_type, "LOW")


# ============================================================
# 7. ANOMALY OBJECT FACTORY
# ============================================================

def create_anomaly(anomaly_type, event, reason):
    """Create a standardized anomaly record dictionary."""
    return {
        "type": anomaly_type,
        "time": event.get("time", "UNKNOWN"),
        "user": event.get("user", "UNKNOWN"),
        "action": event.get("action", "UNKNOWN"),
        "severity": calculate_severity(anomaly_type),
        "reason": reason,
    }


# ============================================================
# 8. HUMAN READABLE EXPLANATIONS
# ============================================================

def generate_explanation(anomaly):
    """Provide detailed forensic explanation for an anomaly."""
    anomaly_type = anomaly.get("type", "")
    user = anomaly.get("user", "UNKNOWN")
    action = anomaly.get("action", "UNKNOWN")
    reason = anomaly.get("reason", "")

    templates = {
        "UNKNOWN_ACTION": f"Unrecognized action '{action}' executed by user '{user}'. Possible evasion or unsupported verb.",
        "DUPLICATE_LOGIN": f"User '{user}' attempted login while a previous active session was already established.",
        "LOGOUT_WITHOUT_LOGIN": f"User '{user}' issued a logout command without an existing active session.",
        "ACTION_WHILE_LOGGED_OUT": f"Unauthorized execution: User '{user}' performed '{action}' while logged out.",
        "MISSING_PREREQUISITE": f"Integrity violation: {reason}",
        "PREREQUISITE_TIMEOUT": f"Session window elapsed: {reason}",
        "SESSION_EXPIRED": f"Inactivity expiration: {reason}",
        "RAPID_BURST": f"Automated rate anomaly: {reason}",
        "TIME_ORDER": f"Timeline anomaly: {reason}",
        "MALFORMED_EVENT": f"Data integrity error: {reason}",
    }

    return templates.get(anomaly_type, reason)


# ============================================================
# 9. STATE MACHINE & SINGLE EVENT ANALYSIS
# ============================================================

def analyze_event(event, user_state):
    """
    Analyze one chronologically ordered event against user session state.

    user_state structure:
    {
        "logged_in": bool,
        "session_history": set(),          # Cleared on logout
        "session_action_times": dict(),    # action -> epoch timestamp
        "all_time_history": set(),         # Persists across sessions
        "last_activity_epoch": float,
    }
    """
    anomalies = []
    action = event["action"]
    _, current_epoch, _ = parse_event_time(event["time"])

    # 1. Check for Unknown Action
    if action not in KNOWN_ACTIONS:
        anomalies.append(
            create_anomaly(
                "UNKNOWN_ACTION",
                event,
                f"Action '{action}' is not in the recognized actions list.",
            )
        )
        return anomalies

    # 2. Check for Rapid Burst / Bot-like Activity
    if (
        user_state["last_activity_epoch"] is not None
        and current_epoch is not None
        and RAPID_BURST_THRESHOLD > 0
    ):
        delta = current_epoch - user_state["last_activity_epoch"]
        if 0 <= delta < RAPID_BURST_THRESHOLD and action != "login":
            anomalies.append(
                create_anomaly(
                    "RAPID_BURST",
                    event,
                    f"Sub-second execution delta ({delta:.4f}s) between actions indicates potential script/bot execution.",
                )
            )

    # 3. Handle Login
    if action == "login":
        if user_state["logged_in"]:
            anomalies.append(
                create_anomaly(
                    "DUPLICATE_LOGIN",
                    event,
                    "User initiated a login while an active session was already recorded.",
                )
            )

        # Reset active session scope
        user_state["logged_in"] = True
        user_state["session_history"] = {"login"}
        user_state["session_action_times"] = {"login": current_epoch}
        user_state["all_time_history"].add("login")
        user_state["last_activity_epoch"] = current_epoch
        return anomalies

    # 4. Handle Logout
    if action == "logout":
        if not user_state["logged_in"]:
            anomalies.append(
                create_anomaly(
                    "LOGOUT_WITHOUT_LOGIN",
                    event,
                    "Logout event occurred while user had no active session.",
                )
            )

        # Terminate active session and clear session-bound history
        user_state["logged_in"] = False
        user_state["session_history"] = set()
        user_state["session_action_times"] = {}
        user_state["all_time_history"].add("logout")
        user_state["last_activity_epoch"] = current_epoch
        return anomalies

    # 5. Check Session Requirement
    if action in SESSION_REQUIRED_ACTIONS:
        if not user_state["logged_in"]:
            anomalies.append(
                create_anomaly(
                    "ACTION_WHILE_LOGGED_OUT",
                    event,
                    f"Action '{action}' requires an active authenticated session.",
                )
            )
        else:
            # Check for Session Inactivity Timeout
            if (
                SESSION_TIMEOUT_SECONDS is not None
                and user_state["last_activity_epoch"] is not None
                and current_epoch is not None
            ):
                idle_duration = current_epoch - user_state["last_activity_epoch"]
                if idle_duration > SESSION_TIMEOUT_SECONDS:
                    anomalies.append(
                        create_anomaly(
                            "SESSION_EXPIRED",
                            event,
                            f"Action '{action}' attempted after {idle_duration:.1f}s of inactivity (timeout is {SESSION_TIMEOUT_SECONDS}s).",
                        )
                    )

    # 6. Check Prerequisite Rules (Must be satisfied within the active session)
    prerequisites = SESSION_RULES.get(action, [])
    for prereq in prerequisites:
        if prereq not in user_state["session_history"]:
            anomalies.append(
                create_anomaly(
                    "MISSING_PREREQUISITE",
                    event,
                    f"Action '{action}' requires prerequisite '{prereq}' to have occurred within the current active session.",
                )
            )
        else:
            # Check for Prerequisite Time Window Expiration
            window_key = (action, prereq)
            if window_key in PREREQUISITE_TIME_WINDOWS and current_epoch is not None:
                max_window = PREREQUISITE_TIME_WINDOWS[window_key]
                prereq_time = user_state["session_action_times"].get(prereq)
                if prereq_time is not None:
                    elapsed = current_epoch - prereq_time
                    if elapsed > max_window:
                        anomalies.append(
                            create_anomaly(
                                "PREREQUISITE_TIMEOUT",
                                event,
                                f"Elapsed time between '{prereq}' and '{action}' was {elapsed:.1f}s, exceeding maximum window of {max_window}s.",
                            )
                        )

    # 7. Update State
    user_state["session_history"].add(action)
    user_state["session_action_times"][action] = current_epoch
    user_state["all_time_history"].add(action)
    user_state["last_activity_epoch"] = current_epoch

    return anomalies


# ============================================================
# 10. DETECT ALL ANOMALIES
# ============================================================

def detect_anomalies(events):
    """
    Full forensic pipeline across all events.
    Preserves original order checks, then analyzes chronological state changes.
    """
    anomalies = []

    # 1. Timeline integrity inspection (on original input order)
    anomalies.extend(detect_time_order_anomalies(events))

    # 2. Chronological sequence analysis
    chronological_events = sort_events(events)
    user_states = {}

    for event in chronological_events:
        valid, error = validate_event(event)
        if not valid:
            anomalies.append(create_anomaly("MALFORMED_EVENT", event, error))
            continue

        user = event["user"]
        if user not in user_states:
            user_states[user] = {
                "logged_in": False,
                "session_history": set(),
                "session_action_times": {},
                "all_time_history": set(),
                "last_activity_epoch": None,
            }

        event_anomalies = analyze_event(event, user_states[user])
        anomalies.extend(event_anomalies)

    return anomalies


# ============================================================
# 11. FORENSIC STATISTICS
# ============================================================

def count_by_key(items, key):
    """Count dictionary values grouped by a key."""
    counts = {}
    for item in items:
        val = item.get(key, "UNKNOWN")
        counts[val] = counts.get(val, 0) + 1
    return counts


def get_statistics(events, anomalies):
    """Calculate comprehensive forensic metrics."""
    total_events = len(events)
    total_anomalies = len(anomalies)

    severity_counts = count_by_key(anomalies, "severity") if anomalies else {}
    user_counts = count_by_key(anomalies, "user") if anomalies else {}
    action_counts = count_by_key(anomalies, "action") if anomalies else {}
    type_counts = count_by_key(anomalies, "type") if anomalies else {}

    anomaly_rate = round((total_anomalies / total_events) * 100, 2) if total_events > 0 else 0.0
    most_common_anomaly = max(type_counts, key=type_counts.get) if type_counts else None

    # Severity distribution percentages
    severity_pct = {}
    if total_anomalies > 0:
        for sev, cnt in severity_counts.items():
            severity_pct[sev] = round((cnt / total_anomalies) * 100, 1)

    return {
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "severity_counts": severity_counts,
        "severity_percentages": severity_pct,
        "user_counts": user_counts,
        "action_counts": action_counts,
        "type_counts": type_counts,
        "anomaly_rate": anomaly_rate,
        "most_common_anomaly": most_common_anomaly,
    }


# ============================================================
# 12. TERMINAL REPORTS
# ============================================================

def generate_report(events, anomalies):
    """Print a clean, structured forensic terminal report."""
    stats = get_statistics(events, anomalies)

    print()
    print("=" * 60)
    print("                TRACE-X FORENSIC REPORT               ")
    print("=" * 60)
    print(f"Total Events Analyzed : {stats['total_events']}")
    print(f"Anomalies Detected    : {stats['total_anomalies']}")
    print(f"Anomaly Rate          : {stats['anomaly_rate']}%")
    print(f"Most Frequent Anomaly : {stats['most_common_anomaly'] or 'None'}")
    print("-" * 60)
    print("Severity Breakdown:")
    sev = stats["severity_counts"]
    print(f"  [CRITICAL/HIGH] : {sev.get('HIGH', 0)}")
    print(f"  [MEDIUM]        : {sev.get('MEDIUM', 0)}")
    print(f"  [LOW]           : {sev.get('LOW', 0)}")
    print("=" * 60)

    if not anomalies:
        print(">> No forensic anomalies detected. Timeline verified clean.")
        return

    print("\n--- DETAILED ANOMALY LOG ---")
    for idx, anomaly in enumerate(anomalies, start=1):
        print(f"\n[#{idx}] [{anomaly['severity']}] {anomaly['type']}")
        print(f"     Time   : {anomaly['time']}")
        print(f"     User   : {anomaly['user']}")
        print(f"     Action : {anomaly['action']}")
        print(f"     Reason : {generate_explanation(anomaly)}")
    print("=" * 60)


def show_anomalies(anomalies):
    """Print only detected anomalies in concise cards."""
    if not anomalies:
        print("\nNo anomalies detected.")
        return

    print("\n========== DETECTED ANOMALIES ==========")
    for idx, anomaly in enumerate(anomalies, start=1):
        print(f"\n#{idx} | [{anomaly['severity']}] {anomaly['type']}")
        print(f"   Time   : {anomaly['time']}")
        print(f"   User   : {anomaly['user']}")
        print(f"   Action : {anomaly['action']}")
        print(f"   Detail : {generate_explanation(anomaly)}")


def show_statistics(events, anomalies):
    """Display comprehensive forensic statistics in console."""
    stats = get_statistics(events, anomalies)

    print("\n========== FORENSIC METRICS ==========")
    print(f"Events Processed : {stats['total_events']}")
    print(f"Total Anomalies  : {stats['total_anomalies']}")
    print(f"Anomaly Ratio    : {stats['anomaly_rate']}%")
    print()

    print("Distribution by Severity:")
    for sev in ["HIGH", "MEDIUM", "LOW"]:
        cnt = stats["severity_counts"].get(sev, 0)
        pct = stats["severity_percentages"].get(sev, 0.0)
        print(f"  - {sev:<7}: {cnt} ({pct}%)")

    print("\nAnomalies by User:")
    for user, cnt in sorted(stats["user_counts"].items(), key=lambda x: x[1], reverse=True):
        print(f"  - {user:<12}: {cnt}")

    print("\nAnomalies by Type:")
    for anom_type, cnt in sorted(stats["type_counts"].items(), key=lambda x: x[1], reverse=True):
        print(f"  - {anom_type:<25}: {cnt}")


# ============================================================
# 13. REPORT EXPORTERS (HTML / CSV / JSON)
# ============================================================

def export_report_json(events, anomalies, filename="tracex_report.json"):
    """Export forensic results and metadata to formatted JSON."""
    stats = get_statistics(events, anomalies)
    payload = {
        "engine": "TraceX Forensics v2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "statistics": stats,
        "anomalies": anomalies,
    }
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"Successfully exported JSON report to: {filename}")
        return True
    except OSError as err:
        print(f"Error exporting JSON report: {err}")
        return False


def export_report_csv(anomalies, filename="tracex_report.csv"):
    """Export detected anomalies to CSV for spreadsheet analysis."""
    if not anomalies:
        print("No anomalies to export.")
        return False
    try:
        fieldnames = ["id", "time", "user", "action", "type", "severity", "reason", "explanation"]
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for idx, anom in enumerate(anomalies, start=1):
                writer.writerow({
                    "id": idx,
                    "time": anom.get("time"),
                    "user": anom.get("user"),
                    "action": anom.get("action"),
                    "type": anom.get("type"),
                    "severity": anom.get("severity"),
                    "reason": anom.get("reason"),
                    "explanation": generate_explanation(anom),
                })
        print(f"Successfully exported CSV report to: {filename}")
        return True
    except OSError as err:
        print(f"Error exporting CSV report: {err}")
        return False


def export_report_html(events, anomalies, filename="tracex_report.html"):
    """
    Generate an interactive, executive-grade HTML forensic report
    with modern dark/light styling, KPI counters, and filterable tables.
    """
    stats = get_statistics(events, anomalies)
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Generate rows for anomaly table
    anomaly_rows = []
    for idx, a in enumerate(anomalies, start=1):
        sev = a.get("severity", "LOW")
        sev_class = {
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low",
        }.get(sev, "badge-low")

        row = f"""
        <tr>
            <td><strong>#{idx}</strong></td>
            <td><code>{a.get('time')}</code></td>
            <td><strong>{a.get('user')}</strong></td>
            <td><code>{a.get('action')}</code></td>
            <td><span class="badge {sev_class}">{sev}</span></td>
            <td><strong>{a.get('type')}</strong></td>
            <td>{generate_explanation(a)}</td>
        </tr>
        """
        anomaly_rows.append(row)

    table_content = "\n".join(anomaly_rows) if anomaly_rows else '<tr><td colspan="7" style="text-align:center; padding:2rem;">No anomalies detected. Timeline verified clean.</td></tr>'

    html_code = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraceX Forensics Report</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --surface: #ffffff;
            --border: #e2e8f0;
            --text: #334155;
            --text-heading: #0f172a;
            --text-muted: #64748b;
            --accent: #2563eb;
            --high: #dc2626;
            --med: #d97706;
            --low: #16a34a;
            --code-bg: #f1f5f9;
            --code-border: #e2e8f0;
            --badge-high-bg: #fee2e2;
            --badge-med-bg: #fef3c7;
            --badge-low-bg: #dcfce7;
            --shadow: 0 1px 3px rgba(0, 0, 0, 0.06), 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            --card-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
            --row-hover: #f8fafc;
        }}

        [data-theme="dark"] {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-heading: #f0f6fc;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --high: #f85149;
            --med: #d29922;
            --low: #3fb950;
            --code-bg: #21262d;
            --code-border: #30363d;
            --badge-high-bg: rgba(248, 81, 73, 0.15);
            --badge-med-bg: rgba(210, 153, 34, 0.15);
            --badge-low-bg: rgba(63, 185, 80, 0.15);
            --shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
            --card-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            --row-hover: #1c2128;
        }}

        * {{
            box-sizing: border-box;
            transition: background-color 0.2s ease, color 0.2s ease, border-color 0.2s ease;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 1.25rem 0.75rem;
            line-height: 1.6;
        }}

        .container {{
            max-width: 98%;
            width: 100%;
            margin: 0 auto;
        }}

        header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem 1.75rem;
            margin-bottom: 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: var(--shadow);
        }}

        .logo-area h1 {{
            margin: 0;
            color: var(--text-heading);
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .logo-badge {{
            background: #dbeafe;
            color: #1d4ed8;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            text-transform: uppercase;
        }}

        [data-theme="dark"] .logo-badge {{
            background: rgba(56, 139, 253, 0.15);
            color: #58a6ff;
        }}

        .subtitle {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 0.35rem;
        }}

        .header-actions {{
            display: flex;
            align-items: center;
            gap: 1.25rem;
        }}

        .meta-timestamp {{
            text-align: right;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}

        .theme-toggle-btn {{
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.5rem 0.9rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }}

        .theme-toggle-btn:hover {{
            border-color: var(--accent);
            color: var(--accent);
        }}

        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}

        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.35rem 1.5rem;
            box-shadow: var(--shadow);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }}

        .kpi-label {{
            font-size: 0.825rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }}

        .kpi-value {{
            font-size: 2.25rem;
            font-weight: 800;
            color: var(--text-heading);
            margin-top: 0.5rem;
            line-height: 1.1;
        }}

        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.25rem;
            box-shadow: var(--card-shadow);
        }}

        .content-grid {{
            display: grid;
            grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr);
            gap: 1.25rem;
            align-items: start;
            margin-bottom: 1.5rem;
        }}

        @media (max-width: 1150px) {{
            .content-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .charts-column {{
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }}

        .chart-box {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.85rem;
            text-align: center;
        }}

        .chart-box h3 {{
            font-size: 0.9rem;
            color: var(--text-heading);
            margin: 0 0 0.6rem 0;
            font-weight: 600;
        }}

        .chart-box img {{
            max-width: 100%;
            max-height: 235px;
            object-fit: contain;
            border-radius: 6px;
            box-shadow: var(--shadow);
            display: block;
            margin: 0 auto;
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border);
        }}

        .card-header h2 {{
            margin: 0;
            color: var(--text-heading);
            font-size: 1.25rem;
            font-weight: 700;
        }}

        table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            text-align: left;
            font-size: 0.925rem;
        }}

        th {{
            background: var(--bg);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.775rem;
            letter-spacing: 0.05em;
            padding: 0.75rem 1rem;
            border-bottom: 2px solid var(--border);
        }}

        td {{
            padding: 0.9rem 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }}

        tr:hover td {{
            background: var(--row-hover);
        }}

        code {{
            background: var(--code-bg);
            border: 1px solid var(--code-border);
            color: var(--text-heading);
            padding: 0.2rem 0.45rem;
            border-radius: 5px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85em;
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.65rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}

        .badge-high {{
            background: var(--badge-high-bg);
            color: var(--high);
            border: 1px solid var(--high);
        }}

        .badge-medium {{
            background: var(--badge-med-bg);
            color: var(--med);
            border: 1px solid var(--med);
        }}

        .badge-low {{
            background: var(--badge-low-bg);
            color: var(--low);
            border: 1px solid var(--low);
        }}

        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 3rem;
            padding-top: 1rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <h1>TraceX Forensics <span class="logo-badge">v2.0</span></h1>
                <div class="subtitle">Deterministic Event Timeline Forensics Engine &amp; Incident Report</div>
            </div>
            <div class="header-actions">
                <div class="meta-timestamp">
                    <div><strong>Report Generated</strong></div>
                    <div>{gen_time}</div>
                </div>
                <button class="theme-toggle-btn" id="themeToggleBtn" onclick="toggleTheme()">
                    <span id="themeIcon">🌙</span> <span id="themeText">Dark Mode</span>
                </button>
            </div>
        </header>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Events Analyzed</div>
                <div class="kpi-value">{stats['total_events']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Anomalies Detected</div>
                <div class="kpi-value" style="color: {'var(--high)' if stats['total_anomalies'] > 0 else 'var(--low)'}">{stats['total_anomalies']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Anomaly Ratio</div>
                <div class="kpi-value">{stats['anomaly_rate']}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Critical / High Incidents</div>
                <div class="kpi-value" style="color: var(--high)">{stats['severity_counts'].get('HIGH', 0)}</div>
            </div>
        </div>

        <div class="content-grid">
            <!-- Left Column: Findings Table (الذي فوقه على اليسار) -->
            <div class="card">
                <div class="card-header">
                    <h2>Forensic Findings &amp; Timeline Violations</h2>
                </div>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Time</th>
                                <th>User</th>
                                <th>Action</th>
                                <th>Severity</th>
                                <th>Violation Type</th>
                                <th>Forensic Investigation Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {table_content}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Right Column: Visualizations & Analytics (هذا على اليمين) -->
            <div class="card">
                <div class="card-header">
                    <h2>Forensic Visualizations &amp; Incident Analytics</h2>
                </div>
                <div class="charts-column">
                    <div class="chart-box">
                        <h3>Anomalies by Severity Distribution</h3>
                        <img src="tracex_severity_chart.png" alt="Severity Chart" onerror="this.parentElement.style.display='none'" />
                    </div>
                    <div class="chart-box">
                        <h3>Temporal Anomaly Frequency</h3>
                        <img src="tracex_timeline_chart.png" alt="Timeline Chart" onerror="this.parentElement.style.display='none'" />
                    </div>
                </div>
            </div>
        </div>

        <footer>
            TraceX Timeline Forensics Engine &bull; Pure Python &bull; Confidential Incident Documentation
        </footer>
    </div>

    <script>
        function toggleTheme() {{
            const html = document.documentElement;
            const current = html.getAttribute('data-theme') || 'light';
            const next = current === 'light' ? 'dark' : 'light';
            html.setAttribute('data-theme', next);

            const icon = document.getElementById('themeIcon');
            const text = document.getElementById('themeText');
            if (next === 'dark') {{
                icon.textContent = '☀️';
                text.textContent = 'Light Mode';
            }} else {{
                icon.textContent = '🌙';
                text.textContent = 'Dark Mode';
            }}
        }}
    </script>
</body>
</html>
"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_code)
        print(f"Successfully generated HTML report: {filename}")
        return True
    except OSError as err:
        print(f"Error generating HTML report: {err}")
        return False


# ============================================================
# 14. VISUALIZATION (CHARTS)
# ============================================================

def plot_anomalies(anomalies, save_path=None, show=True):
    """Plot anomalies categorized by severity."""
    if not anomalies:
        print("No anomalies to plot.")
        return

    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for anomaly in anomalies:
        sev = anomaly.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    severities = ["LOW", "MEDIUM", "HIGH"]
    counts = [severity_counts.get(s, 0) for s in severities]
    colors = ["#16a34a", "#d97706", "#dc2626"]

    plt.figure(figsize=(7, 3.2))
    bars = plt.bar(severities, counts, color=colors, edgecolor="#cbd5e1", width=0.55)

    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, h + 0.08, f"{int(h)}", ha="center", va="bottom", fontweight="bold")

    plt.title("TraceX: Anomalies by Severity Level", fontsize=12, fontweight="bold", pad=12)
    plt.xlabel("Severity Level", labelpad=8)
    plt.ylabel("Anomaly Count", labelpad=8)
    plt.ylim(0, max(counts) + 1.5 if max(counts) > 0 else 5)
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=200)
        print(f"Saved severity chart to: {save_path}")

    if show:
        try:
            plt.show()
        except Exception:
            pass
    plt.close()


def plot_anomalies_over_time(anomalies, save_path=None, show=True):
    """Plot distribution of anomalies across the timeline."""
    if not anomalies:
        print("No anomalies to plot.")
        return

    parsed_times = []
    for anom in anomalies:
        valid, epoch, _ = parse_event_time(anom.get("time"))
        if valid and epoch is not None:
            parsed_times.append(epoch)

    if not parsed_times:
        print("No numeric or parseable timestamps found for timeline plot.")
        return

    counts_by_time = {}
    for t in parsed_times:
        counts_by_time[t] = counts_by_time.get(t, 0) + 1

    x_vals = sorted(counts_by_time.keys())
    y_vals = [counts_by_time[t] for t in x_vals]

    plt.figure(figsize=(7.5, 3.2))
    plt.plot(x_vals, y_vals, marker="o", linewidth=2.5, color="#2563eb", markersize=6)
    plt.title("TraceX: Timeline Frequency of Detected Anomalies", fontsize=12, fontweight="bold", pad=12)
    plt.xlabel("Timeline (Normalized Epoch / Step)", labelpad=8)
    plt.ylabel("Anomalies per Timestamp", labelpad=8)
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=200)
        print(f"Saved timeline chart to: {save_path}")

    if show:
        try:
            plt.show()
        except Exception:
            pass
    plt.close()


# ============================================================
# 15. LOG LOADING (JSON & JSON LINES / .JSONL)
# ============================================================

def load_events_from_file(filename):
    """
    Load forensic events from either a standard JSON file or a JSON Lines (.jsonl) file.
    """
    if not os.path.isfile(filename):
        print(f"Error: File '{filename}' was not found.")
        return []

    try:
        if filename.endswith(".jsonl") or filename.endswith(".ndjson"):
            events = []
            with open(filename, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, start=1):
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        obj = json.loads(line_str)
                        events.append(obj)
                    except json.JSONDecodeError as err:
                        print(f"Warning: Line {line_idx} skipped (JSONDecodeError: {err})")
            return events

        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            print("Error: JSON file root must contain a list of event objects.")
            return []

        return data

    except json.JSONDecodeError:
        try:
            events = []
            with open(filename, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str:
                        events.append(json.loads(line_str))
            if events:
                print("Note: File loaded successfully as JSON Lines (line-delimited JSON).")
                return events
        except Exception:
            pass

        print("Error: Invalid JSON format.")
        return []
    except OSError as err:
        print(f"Error reading file '{filename}': {err}")
        return []


# ============================================================
# 16. DISPLAY EVENTS
# ============================================================

def show_events(events):
    """Print events in a clean chronological table."""
    if not events:
        print("\nNo events available.")
        return

    print("\n" + "=" * 65)
    print("                     RECORDED EVENTS                     ")
    print("=" * 65)
    print(f"{'TIME':<22} | {'USER':<15} | {'ACTION':<20}")
    print("-" * 65)

    for event in sort_events(events):
        t = str(event.get("time", "UNKNOWN"))
        u = str(event.get("user", "UNKNOWN"))
        a = str(event.get("action", "UNKNOWN"))
        print(f"{t:<22} | {u:<15} | {a:<20}")
    print("=" * 65)


# ============================================================
# 17. COMPLETE ANALYSIS PIPELINE
# ============================================================

def analyze_dataset(events, silent=False):
    """Run full TraceX forensic analysis on dataset."""
    if not events:
        if not silent:
            print("\nThere are no events to analyze.")
        return []

    validation_problems = validate_events(events)
    if validation_problems and not silent:
        print("\n========== VALIDATION WARNINGS ==========")
        for p in validation_problems:
            print(f"Event #{p['index']}: {p['error']}")

    anomalies = detect_anomalies(events)

    if not silent:
        generate_report(events, anomalies)

    return anomalies


# ============================================================
# 18. AUTOMATED REGRESSION & VERIFICATION SUITE
# ============================================================

def run_self_test():
    """Run built-in automated test suite verifying detection accuracy."""
    print("\nRunning TraceX self-diagnostic suite...")

    anomalies = detect_anomalies(SAMPLE_EVENTS)
    types_found = {a["type"] for a in anomalies}

    expected_types = {
        "ACTION_WHILE_LOGGED_OUT",
        "DUPLICATE_LOGIN",
        "UNKNOWN_ACTION",
        "LOGOUT_WITHOUT_LOGIN",
        "MISSING_PREREQUISITE",
    }

    assert expected_types.issubset(types_found), f"Missing expected anomalies: {expected_types - types_found}"
    print("[PASS] Test 1: Core rule violations detected correctly.")

    iso_events = [
        {"time": "2026-09-22T10:00:00Z", "user": "bob", "action": "login"},
        {"time": "2026-09-22T09:00:00Z", "user": "bob", "action": "read"},
    ]
    time_order_anoms = detect_anomalies(iso_events)
    assert any(a["type"] == "TIME_ORDER" for a in time_order_anoms), "Failed to catch ISO time order anomaly"
    print("[PASS] Test 2: ISO-8601 parsing and backwards time detection.")

    session_events = [
        {"time": 1, "user": "claire", "action": "login"},
        {"time": 2, "user": "claire", "action": "order_created"},
        {"time": 3, "user": "claire", "action": "logout"},
        {"time": 4, "user": "claire", "action": "login"},
        {"time": 5, "user": "claire", "action": "payment"},
    ]
    sess_anoms = detect_anomalies(session_events)
    assert any(a["type"] == "MISSING_PREREQUISITE" for a in sess_anoms), "Failed to enforce session-bound prerequisite reset on logout"
    print("[PASS] Test 3: Session clearance and cross-session isolation.")

    print("\nAll self-tests completed successfully! (3/3 passed)")
    return True


# ============================================================
# 19. INTERACTIVE CLI MENU
# ============================================================

def main():
    current_events = SAMPLE_EVENTS.copy()
    current_anomalies = []

    while True:
        print()
        print("=" * 55)
        print("                 TRACE-X v2.0                 ")
        print("       Event Timeline Forensics Engine        ")
        print("=" * 55)
        print("1. Analyze current events")
        print("2. Load events file (JSON / JSON Lines .jsonl)")
        print("3. Show events table")
        print("4. Show detected anomalies")
        print("5. Show forensic metrics & statistics")
        print("6. Plot anomalies by severity")
        print("7. Plot anomalies over timeline")
        print("8. Export report (HTML / CSV / JSON)")
        print("9. Run self-test suite")
        print("10. Exit")
        print()

        choice = input("Choose an option [1-10]: ").strip()

        if choice == "1":
            current_anomalies = analyze_dataset(current_events)

        elif choice == "2":
            path = input("Enter file path (.json or .jsonl): ").strip()
            loaded = load_events_from_file(path)
            if loaded:
                current_events = loaded
                current_anomalies = []
                print(f"\nLoaded {len(current_events)} events from {path}")

        elif choice == "3":
            show_events(current_events)

        elif choice == "4":
            if not current_anomalies:
                print("\nRunning analysis first...")
                current_anomalies = analyze_dataset(current_events, silent=True)
            show_anomalies(current_anomalies)

        elif choice == "5":
            if not current_anomalies:
                current_anomalies = analyze_dataset(current_events, silent=True)
            show_statistics(current_events, current_anomalies)

        elif choice == "6":
            if not current_anomalies:
                current_anomalies = analyze_dataset(current_events, silent=True)
            plot_anomalies(current_anomalies, save_path="tracex_severity_chart.png", show=True)

        elif choice == "7":
            if not current_anomalies:
                current_anomalies = analyze_dataset(current_events, silent=True)
            plot_anomalies_over_time(current_anomalies, save_path="tracex_timeline_chart.png", show=True)

        elif choice == "8":
            if not current_anomalies:
                print("\nAnalyzing dataset first before export...")
                current_anomalies = analyze_dataset(current_events, silent=True)

            print("\nExport Formats:")
            print("  a. HTML Forensic Dashboard (Interactive)")
            print("  b. CSV Report (Excel-compatible)")
            print("  c. JSON Report (Machine-readable)")
            exp_choice = input("Select format [a/b/c]: ").strip().lower()

            if exp_choice == "a":
                plot_anomalies(current_anomalies, save_path="tracex_severity_chart.png", show=False)
                plot_anomalies_over_time(current_anomalies, save_path="tracex_timeline_chart.png", show=False)
                export_report_html(current_events, current_anomalies)
            elif exp_choice == "b":
                export_report_csv(current_anomalies)
            elif exp_choice == "c":
                export_report_json(current_events, current_anomalies)
            else:
                print("Invalid export format selected.")

        elif choice == "9":
            run_self_test()

        elif choice == "10":
            print("\nTraceX Forensics Engine terminated.")
            break

        else:
            print("\nInvalid choice. Please choose a number from 1 to 10.")


# ============================================================
# 20. PROGRAM ENTRY POINT
# ============================================================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_self_test()
    else:
        anomalies = analyze_dataset(SAMPLE_EVENTS)
        show_anomalies(anomalies)
        show_statistics(SAMPLE_EVENTS, anomalies)

        # Generate & save high-res forensic visualization charts
        print("\nGenerating forensic timeline charts...")
        plot_anomalies(anomalies, save_path="tracex_severity_chart.png", show=False)
        plot_anomalies_over_time(anomalies, save_path="tracex_timeline_chart.png", show=False)

        # Export default HTML report with charts embedded
        export_report_html(SAMPLE_EVENTS, anomalies, "tracex_demo_report.html")
        print("\n[+] Demonstration report ready: tracex_demo_report.html")
        print("[+] Severity chart saved: tracex_severity_chart.png")
        print("[+] Timeline chart saved: tracex_timeline_chart.png")

