"""Login Log Analyser - a small tool for spotting suspicious login activity.

It reads an SSH-style auth log and looks for:
  1. Brute-force attempts  - many failed logins from one IP in a short time
  2. Unusual-hour logins   - successful logins late at night / early morning
  3. Possible compromise   - a successful login right after a brute-force burst

Usage:  python log_analyser.py sample_logs/auth.log
        python log_analyser.py auth.log --threshold 5 --window 5 --night-start 0 --night-end 6
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------- appearance
# ANSI colour codes. They make the report easier to read in a terminal.
if os.name == "nt":
    os.system("")  # tiny trick that switches on colour support in Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # so box-drawing characters print correctly

RED, YELLOW, GREEN, CYAN = "\033[91m", "\033[93m", "\033[92m", "\033[96m"
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
WIDTH = 72


def banner(text):
    """Print a boxed title."""
    print(f"{CYAN}{BOLD}╔{'═' * (WIDTH - 2)}╗")
    print(f"║{text.center(WIDTH - 2)}║")
    print(f"╚{'═' * (WIDTH - 2)}╝{RESET}")


def section(title, colour):
    """Print a coloured section heading with a line under it."""
    print(f"\n{colour}{BOLD}▌ {title}{RESET}")
    print(f"{DIM}{'─' * WIDTH}{RESET}")


# ------------------------------------------------------------------- parsing
# This pattern pulls the useful parts out of each log line.
LINE_PATTERN = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .*?"
    r"(?P<result>Accepted|Failed) password for (?P<user>\S+) from (?P<ip>\S+)"
)


def parse_log(path):
    """Read the file and return a list of events (dicts). Unreadable lines are skipped."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            match = LINE_PATTERN.match(line)
            if match:
                events.append({
                    "time": datetime.strptime(match["time"], "%Y-%m-%d %H:%M:%S"),
                    "success": match["result"] == "Accepted",
                    "user": match["user"],
                    "ip": match["ip"],
                })
    return events


# ----------------------------------------------------------------- detection
def find_brute_force(events, threshold, window_minutes):
    """Find IPs with `threshold` or more failures inside any `window_minutes` window.

    Returns a dict: ip -> info about the worst burst.
    """
    window = timedelta(minutes=window_minutes)
    failures_by_ip = defaultdict(list)
    for e in events:
        if not e["success"]:
            failures_by_ip[e["ip"]].append(e)

    results = {}
    for ip, fails in failures_by_ip.items():
        fails.sort(key=lambda e: e["time"])
        start = 0
        best = None  # (count, first_event, last_event)
        # Sliding window: move `start` forward until the window is small enough.
        for end in range(len(fails)):
            while fails[end]["time"] - fails[start]["time"] > window:
                start += 1
            count = end - start + 1
            if count >= threshold and (best is None or count > best[0]):
                best = (count, fails[start], fails[end])
        if best:
            burst = [e for e in fails if best[1]["time"] <= e["time"] <= best[2]["time"]]
            results[ip] = {
                "count": best[0],
                "first": best[1]["time"],
                "last": best[2]["time"],
                "users": sorted({e["user"] for e in burst}),
                "total_failures": len(fails),
            }
    return results


def find_unusual_hours(events, night_start, night_end):
    """Return successful logins that happened between night_start and night_end (hours)."""
    return [e for e in events if e["success"] and night_start <= e["time"].hour < night_end]


def find_compromises(events, brute_force):
    """A success from an IP that was also brute-forcing = likely a breach."""
    hits = []
    for e in events:
        if e["success"] and e["ip"] in brute_force and e["time"] >= brute_force[e["ip"]]["first"]:
            hits.append(e)
    return hits


# ------------------------------------------------------------------- report
def severity(count):
    """Turn a failure count into a label and colour."""
    if count >= 20:
        return "CRITICAL", RED
    if count >= 10:
        return "HIGH", YELLOW
    return "MEDIUM", YELLOW


def bar(count, biggest, length=20):
    """A small text bar chart so the biggest attacker stands out."""
    filled = max(1, round(count / biggest * length))
    return "█" * filled + "░" * (length - filled)


def print_report(path, events, brute_force, odd_hours, compromises, args):
    banner("LOGIN LOG ANALYSER")
    successes = sum(e["success"] for e in events)
    print(f"{DIM}File:{RESET} {path}")
    print(f"{DIM}Events analysed:{RESET} {len(events)}  "
          f"({GREEN}{successes} successful{RESET}, {RED}{len(events) - successes} failed{RESET})")
    if events:
        print(f"{DIM}Time range:{RESET} {events[0]['time']:%Y-%m-%d %H:%M} → {events[-1]['time']:%Y-%m-%d %H:%M}")
    print(f"{DIM}Rules:{RESET} ≥{args.threshold} failures within {args.window} min  |  "
          f"night = {args.night_start:02d}:00–{args.night_end:02d}:00")

    # --- Brute force
    section(f"BRUTE-FORCE ATTEMPTS  ({len(brute_force)} source(s))", RED)
    if brute_force:
        biggest = max(b["count"] for b in brute_force.values())
        ranked = sorted(brute_force.items(), key=lambda kv: -kv[1]["count"])
        for ip, b in ranked[:args.top]:  # args.top is None = show everything
            label, colour = severity(b["count"])
            print(f"{colour}{BOLD}[{label}]{RESET} {BOLD}{ip}{RESET}")
            print(f"   {colour}{bar(b['count'], biggest)}{RESET} {b['count']} failures "
                  f"between {b['first']:%H:%M:%S} and {b['last']:%H:%M:%S} on {b['first']:%Y-%m-%d}")
            print(f"   {DIM}accounts targeted:{RESET} {', '.join(b['users'])}")
        if args.top and len(ranked) > args.top:
            print(f"{DIM}... and {len(ranked) - args.top} more source(s) hidden by --top {args.top}{RESET}")
    else:
        print(f"{GREEN}✔ No brute-force activity detected.{RESET}")

    # --- Compromise
    section(f"POSSIBLE COMPROMISE  ({len(compromises)})", RED)
    if compromises:
        for e in compromises:
            print(f"{RED}{BOLD}⚠ {e['user']}{RESET} logged in from {BOLD}{e['ip']}{RESET} "
                  f"at {e['time']:%Y-%m-%d %H:%M:%S} {RED}— after a brute-force burst from the same IP!{RESET}")
    else:
        print(f"{GREEN}✔ No successful logins from brute-forcing IPs.{RESET}")

    # --- Unusual hours
    section(f"UNUSUAL-HOUR LOGINS  ({len(odd_hours)})", YELLOW)
    if odd_hours:
        for e in odd_hours:
            print(f"{YELLOW}●{RESET} {e['time']:%Y-%m-%d %H:%M:%S}  {BOLD}{e['user']:<8}{RESET} from {e['ip']}")
    else:
        print(f"{GREEN}✔ No logins during unusual hours.{RESET}")

    # --- Summary
    section("SUMMARY", CYAN)
    total_alerts = len(brute_force) + len(compromises) + len(odd_hours)
    colour = RED if compromises else YELLOW if total_alerts else GREEN
    print(f"{colour}{BOLD}{total_alerts} alert(s){RESET}: {len(brute_force)} brute-force source(s), "
          f"{len(compromises)} possible compromise(s), {len(odd_hours)} unusual-hour login(s)")
    if compromises:
        print(f"{RED}Action:{RESET} reset the affected account(s), review what they did, and block the source IP(s).")
    elif brute_force:
        print(f"{YELLOW}Action:{RESET} block the source IP(s) and consider rate-limiting or MFA.")
    print()


# --------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description="Detect brute-force and unusual-hour logins in an auth log.")
    parser.add_argument("logfile", help="path to the log file")
    parser.add_argument("--threshold", type=int, default=5, help="failures needed to flag brute force (default 5)")
    parser.add_argument("--window", type=int, default=5, help="time window in minutes (default 5)")
    parser.add_argument("--night-start", type=int, default=0, help="first 'unusual' hour, 0-23 (default 0)")
    parser.add_argument("--night-end", type=int, default=6, help="hour unusual period ends (default 6)")
    parser.add_argument("--top", type=int, default=None, help="only show the N worst brute-force sources")
    args = parser.parse_args()

    try:
        events = parse_log(args.logfile)
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {args.logfile}")

    events.sort(key=lambda e: e["time"])
    brute_force = find_brute_force(events, args.threshold, args.window)
    odd_hours = find_unusual_hours(events, args.night_start, args.night_end)
    compromises = find_compromises(events, brute_force)
    print_report(args.logfile, events, brute_force, odd_hours, compromises, args)


if __name__ == "__main__":
    main()
