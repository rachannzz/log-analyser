"""Generate realistic sample login logs for testing log_analyser.py.

Run:  python generate_sample_logs.py
Output: sample_logs/auth.log

The log uses the same shape as a simplified SSH auth log:
    2026-10-01 03:12:44 sshd[1234]: Failed password for admin from 203.0.113.45 port 51234
All IP addresses come from the reserved documentation ranges (RFC 5737),
so they are safe, fake addresses.
"""

import os
import random
from datetime import datetime, timedelta

random.seed(42)  # same seed = same log every time, so results are repeatable

USERS = ["alice", "bob", "carol", "dave", "erin"]
OFFICE_IPS = {  # each employee normally logs in from one internal address
    "alice": "198.51.100.10",
    "bob": "198.51.100.11",
    "carol": "198.51.100.12",
    "dave": "198.51.100.13",
    "erin": "198.51.100.14",
}
START = datetime(2026, 10, 1, 0, 0, 0)

lines = []  # list of (timestamp, text) so we can sort everything at the end


def add(when, outcome, user, ip):
    """Add one log line. outcome is 'Accepted' or 'Failed'."""
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 65000)
    text = f"{when:%Y-%m-%d %H:%M:%S} sshd[{pid}]: {outcome} password for {user} from {ip} port {port}"
    lines.append((when, text))


# 1. Normal behaviour: staff log in during working hours, with the odd typo.
for day in range(3):
    for user in USERS:
        login = START + timedelta(days=day, hours=random.randint(8, 10), minutes=random.randint(0, 59))
        if random.random() < 0.3:  # occasional mistyped password
            add(login - timedelta(seconds=20), "Failed", user, OFFICE_IPS[user])
        add(login, "Accepted", user, OFFICE_IPS[user])

# 2. Brute-force attack: one outside IP hammers the 'admin' account, 40 tries in ~2 minutes.
attacker = "203.0.113.45"
t = START + timedelta(days=1, hours=14, minutes=5)
for i in range(40):
    add(t + timedelta(seconds=i * 3), "Failed", random.choice(["admin", "root"]), attacker)

# 3. Password spraying: a second attacker tries a few common users slowly but persistently.
sprayer = "203.0.113.77"
t = START + timedelta(days=2, hours=2, minutes=30)
for i in range(12):
    add(t + timedelta(seconds=i * 20), "Failed", random.choice(["test", "oracle", "ubuntu", "admin"]), sprayer)

# 4. A successful break-in: attacker guesses 'carol' password after several failures.
breacher = "192.0.2.99"
t = START + timedelta(days=2, hours=3, minutes=12)
for i in range(8):
    add(t + timedelta(seconds=i * 10), "Failed", "carol", breacher)
add(t + timedelta(seconds=90), "Accepted", "carol", breacher)

# 5. Unusual-hour logins: legitimate accounts, but at times nobody normally works.
add(START + timedelta(hours=3, minutes=47), "Accepted", "dave", "198.51.100.13")
add(START + timedelta(days=1, hours=1, minutes=15), "Accepted", "bob", "198.51.100.11")

# 6. Background noise: a few harmless one-off failures from random addresses.
for _ in range(6):
    when = START + timedelta(days=random.randint(0, 2), hours=random.randint(8, 18), minutes=random.randint(0, 59))
    add(when, "Failed", random.choice(USERS), f"192.0.2.{random.randint(100, 200)}")

# 7. A night-shift worker: frank always logs in around 2am. Normal for him, but a
#    fixed "night hours" rule flags it, while `--learn` correctly learns it is normal.
for day in range(3):
    add(START + timedelta(days=day, hours=2, minutes=random.randint(0, 40)), "Accepted", "frank", "198.51.100.15")

# Sort by time, then write the file.
lines.sort(key=lambda pair: pair[0])
os.makedirs("sample_logs", exist_ok=True)
with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(text for _, text in lines) + "\n")

print(f"Wrote {len(lines)} log lines to sample_logs/auth.log")
