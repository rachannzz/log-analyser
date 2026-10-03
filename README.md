# 🛡️ Login Log Analyser

A small, dependency-free Python tool that reads login logs and flags suspicious activity: **brute-force attacks**, **logins at unusual hours**, and **possible account compromise**. It prints a colour-coded summary report in the terminal.

Built as a beginner cybersecurity portfolio project to practise log analysis, the same core skill SOC analysts use every day.

## Features

- Parses SSH-style authentication logs with a regular expression
- Sliding-window brute-force detection (configurable threshold and window)
- Unusual-hour login detection (configurable "night" hours)
- Correlates events: flags a successful login that follows a brute-force burst from the same IP
- Severity labels, a mini bar chart and a final summary with recommended actions
- Pure Python 3 standard library, with nothing to install

## Project structure

```
log-analyser/
├── log_analyser.py          # the analyser (main tool)
├── generate_sample_logs.py  # creates realistic fake logs for testing
├── sample_logs/auth.log     # generated sample data
└── README.md
```

## Usage

Requires Python 3.8 or newer.

```bash
# 1. (Optional) regenerate the sample log
python generate_sample_logs.py

# 2. Analyse a log file
python log_analyser.py sample_logs/auth.log
```

### Options

| Option | Default | Meaning |
|---|---|---|
| `--threshold` | `5` | Failed logins from one IP needed to flag a brute-force attempt |
| `--window` | `5` | Time window in minutes for counting those failures |
| `--night-start` | `0` | First hour (0-23) considered unusual |
| `--night-end` | `6` | Hour at which the unusual period ends (exclusive) |

Example, with stricter rules:

```bash
python log_analyser.py sample_logs/auth.log --threshold 3 --window 2 --night-start 22 --night-end 6
```

### Expected log format

```
2026-10-01 03:12:44 sshd[1234]: Failed password for admin from 203.0.113.45 port 51234
2026-10-01 09:02:10 sshd[2001]: Accepted password for alice from 198.51.100.10 port 40022
```

Lines that don't match are skipped. To support another format (for example the real `/var/log/auth.log`, which has no year), adjust `LINE_PATTERN` in `log_analyser.py`.

## What it detects and why it matters

### 1. Brute-force attempts
**What:** Many failed logins from one source IP in a short time (default: 5 or more in 5 minutes), found with a sliding time window.

**Why it matters:** Brute-forcing and password guessing are among the most common ways attackers try to get in. Internet-facing SSH, RDP and web logins are probed constantly. Spotting the burst lets you block the IP, add rate limiting or lockouts, and enforce MFA before a guess succeeds.

### 2. Unusual-hour logins
**What:** *Successful* logins between certain hours (default 00:00-06:00).

**Why it matters:** Stolen credentials are often used outside working hours, when nobody is watching. A valid password at 3 a.m. is a classic sign of account takeover or an insider threat. It isn't proof on its own, since the user may be on a night shift or in another time zone, but it is worth a look.

### 3. Possible compromise (correlation)
**What:** A successful login from an IP that was just brute-forcing.

**Why it matters:** This is the most serious finding, because it suggests the attacker **got in**. It turns "someone is attacking us" into "someone may be inside", which is when you reset credentials, investigate and respond to an incident.

## About the sample data

`generate_sample_logs.py` builds three days of fake traffic with a fixed random seed, so the results are repeatable. It contains:

- Normal staff logins in office hours, with the odd typo
- A fast brute-force attack on `admin` / `root`
- A slower password-spraying attack across common usernames
- An attacker who eventually guesses `carol`'s password (the compromise case)
- Two logins at odd hours
- Harmless background noise (single failures)

All IPs are from reserved documentation ranges (RFC 5737), so none belong to real systems.

## Limitations and ideas for improvement

- Only analyses one log format; add parsers for Windows Event Logs or web server logs
- Fixed time-of-day rule; a smarter version would learn each user's normal hours
- No GeoIP or threat-intelligence lookups on source IPs
- Could export results as JSON/CSV or HTML

## Disclaimer

For learning and defensive use on logs you are authorised to analyse.
