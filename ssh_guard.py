"""ssh-guard: read-only analysis of OpenSSH authentication logs.

It flags IP addresses with many failed logins and lists successful logins that
happened after an IP had already been flagged. It only reads a log file: it never
blocks anything and never runs commands.
"""
import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import NamedTuple

MAX_LINE = 4096  # longer lines are counted as malformed instead of being parsed

MONTHS = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

# Two timestamp styles are understood at the start of a line:
#   2026-10-05T10:01:01.123456+00:00   RFC 3339 / ISO 8601 (Ubuntu 22.04+ rsyslog, journalctl -o short-iso)
#   Oct  5 10:01:01                    classic syslog (no year, no time zone)
ISO_TS = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?(?=\s|$)")
SYSLOG_TS = re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})(?=\s|$)")

# "sshd[123]:" (OpenSSH 9.8+ may log "sshd-session[123]:") followed by the message text.
TAGGED = re.compile(r"^(?P<prefix>.*?)\bsshd(?:-session)?(?:\[\d+\])?:\s+(?P<msg>.*)$")

# The user name is matched greedily and the line must END with "from <ip> port <n>".
# A user name is attacker-controlled text; if it contains "from 10.0.0.1 port 22",
# the greedy match still picks the real source address at the end of the message.
EVENT = re.compile(
    r"^(?P<kind>Failed|Accepted) (?P<method>[\w/.-]+) for (?:invalid user )?(?P<user>.+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)(?:\s.*)?$")


class Event(NamedTuple):
    lineno: int
    ts: datetime | None  # None when the line has no readable timestamp
    kind: str            # "failed" or "accepted"
    ip: str
    user: str


def end_of_day(as_of):
    """Turn a date (or datetime) into the latest moment the log could contain."""
    if as_of is None:
        as_of = date.today()
    if isinstance(as_of, datetime):
        return as_of
    return datetime.combine(as_of, time.max)


def parse_timestamp(prefix, as_of_end):
    """Parse the timestamp at the start of `prefix`; return None if there is none.

    Timestamps with a UTC offset are converted to UTC. Classic syslog timestamps have
    no year, so the newest year that is not after `as_of_end` is used. (That is what
    makes "Dec 31" followed by "Jan 1" work across New Year.)
    """
    prefix = prefix.strip()
    if m := ISO_TS.match(prefix):
        year, month, day, hour, minute, second, zone = m.groups()
        try:
            ts = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
            if zone and zone != "Z":
                digits = zone[1:].replace(":", "")
                offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
                ts = ts - offset if zone[0] == "+" else ts + offset
        except (ValueError, OverflowError):
            return None
        return ts
    if m := SYSLOG_TS.match(prefix):
        month = MONTHS.get(m[1])
        if month is None:
            return None
        day, hour, minute, second = (int(x) for x in m.groups()[1:])
        for year in range(as_of_end.year, as_of_end.year - 8, -1):  # 8 years skips leap-day gaps
            try:
                ts = datetime(year, month, day, hour, minute, second)
            except ValueError:
                continue
            if ts <= as_of_end:
                return ts
    return None


def normalize_ip(token):
    """Return the canonical text of a valid IPv4/IPv6 address, else None."""
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:  # also rejects 999.1.1.1, 1.2.3 and zero-padded 01.2.3.4
        return None
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # ::ffff:1.2.3.4 and 1.2.3.4 are the same host
        elif ip.scope_id:
            # "fe80::1%eth0": Python accepts ANY text after the "%", so the scope is dropped
            # instead of being passed on to the report and the blocklist file.
            ip = ipaddress.IPv6Address(int(ip))
    return str(ip)


def parse_events(lines, as_of_end):
    """Turn raw log lines into Events. Returns (events, stats)."""
    stats = {"lines": 0, "failed": 0, "accepted": 0, "malformed": 0, "invalid_ip": 0,
             "repeated_summaries": 0, "skipped_undated": 0, "mode": "dated"}
    events = []
    for lineno, raw in enumerate(lines, start=1):
        stats["lines"] += 1
        line = raw.rstrip("\r\n")
        if len(line) > MAX_LINE:
            stats["malformed"] += 1
            continue
        tagged = TAGGED.match(line)
        prefix, msg = (tagged["prefix"], tagged["msg"]) if tagged else ("", line)
        if msg.startswith("message repeated") and ("Failed " in msg or "Accepted " in msg):
            stats["repeated_summaries"] += 1  # rsyslog summary line: not expanded (see README)
            continue
        if not msg.startswith(("Failed ", "Accepted ")):
            continue  # not an SSH authentication result (includes "Invalid user ..." lines)
        m = EVENT.match(msg)
        if not m:
            stats["malformed"] += 1
            continue
        ip = normalize_ip(m["ip"])
        if ip is None:
            stats["invalid_ip"] += 1
            continue
        kind = m["kind"].lower()
        stats[kind] += 1
        events.append(Event(lineno, parse_timestamp(prefix, as_of_end), kind, ip, m["user"]))
    return events, stats


def check_options(threshold, window):
    for name, value, required in (("threshold", threshold, True), ("window", window, False)):
        if value is None and not required:
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{name} must be a whole number >= 1")


def fmt(ts):
    return ts.isoformat(sep=" ") if ts else None


def safe(text):
    """Escape control and invisible characters (terminal escape sequences, bidirectional overrides,
    ...). User names come from attackers; they must not be able to rewrite what the report shows."""
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def analyze(lines, threshold=5, window=None, as_of=None):
    """Analyze log lines.

    An IP is flagged when it has `threshold` failed logins (inside any `window`
    seconds, if a window is given). Events are processed in timestamp order, so
    out-of-order logs give the same answer. Lines without a readable timestamp are
    skipped (and counted) -- unless NO line has a timestamp, in which case file
    order is used and `window` is not available.
    """
    check_options(threshold, window)
    events, stats = parse_events(lines, end_of_day(as_of))
    dated = [e for e in events if e.ts is not None]
    if dated:
        stats["skipped_undated"] = len(events) - len(dated)
        ordered = sorted(dated, key=lambda e: (e.ts, e.lineno))
    else:
        if window is not None and events:
            raise ValueError("--window needs timestamps, but no SSH log line has a readable one")
        stats["mode"] = "undated"
        ordered = events

    failures, peak = Counter(), Counter()
    users = defaultdict(Counter)
    recent = defaultdict(deque)
    first_seen, last_seen = {}, {}
    flagged, logins = set(), []
    for ev in ordered:
        if ev.kind == "accepted":
            if ev.ip in flagged:
                logins.append({"ip": ev.ip, "user": ev.user, "time": fmt(ev.ts)})
            continue
        failures[ev.ip] += 1
        users[ev.ip][ev.user] += 1
        first_seen.setdefault(ev.ip, ev.ts)
        last_seen[ev.ip] = ev.ts
        if window is None:
            count = failures[ev.ip]
        else:
            times = recent[ev.ip]
            times.append(ev.ts)
            while (ev.ts - times[0]).total_seconds() > window:  # a span of exactly `window` s still counts
                times.popleft()
            count = len(times)
        peak[ev.ip] = max(peak[ev.ip], count)
        if count >= threshold:
            flagged.add(ev.ip)

    suspects = [
        {"ip": ip, "failures": failures[ip],
         "peak_in_window": peak[ip] if window is not None else None,
         "first_seen": fmt(first_seen[ip]), "last_seen": fmt(last_seen[ip]),
         "distinct_users": len(users[ip]), "top_users": [u for u, _ in users[ip].most_common(3)]}
        for ip in sorted(flagged, key=lambda ip: (-failures[ip], ip))
    ]
    return {"suspects": suspects, "suspicious_logins": logins, "stats": stats}


def same_file(first, second):
    """True when both paths exist and are the same file (hard links and symbolic links included)."""
    try:
        return os.path.samefile(first, second)
    except OSError:  # one of them does not exist (yet)
        return False


def write_blocklist(path, suspects):
    """Write flagged IPs, one per line. This only writes a text file; nothing is blocked."""
    ips = sorted({s["ip"] for s in suspects},
                 key=lambda text: (ipaddress.ip_address(text).version, int(ipaddress.ip_address(text))))
    Path(path).write_text("".join(f"{ip}\n" for ip in ips), encoding="utf-8")


def format_report(result, threshold, window):
    s = result["stats"]
    rule = f">= {threshold} failed logins" + (f" within {window}s" if window else "")
    out = [f"Read {s['lines']} lines: {s['failed']} failed and {s['accepted']} accepted SSH logins "
           f"(ordered by {'timestamp' if s['mode'] == 'dated' else 'file position, no timestamps found'})",
           f"Flagged IP addresses ({rule}): {len(result['suspects'])}"]
    for x in result["suspects"]:
        peak = f", peak {x['peak_in_window']} in {window}s" if x["peak_in_window"] else ""
        span = f", {x['first_seen']} to {x['last_seen']}" if x["first_seen"] else ""
        out.append(f"  {x['ip']:<18}{x['failures']:>4} failures{peak}{span}; "
                   f"{x['distinct_users']} user names tried, e.g. {', '.join(safe(u) for u in x['top_users'])}")
    if result["suspicious_logins"]:
        out.append("Successful logins from flagged IPs (a signal worth investigating, not proof of compromise):")
        out += [f"  {x['time'] or '(no time)'}  {safe(x['user'])} from {x['ip']}" for x in result["suspicious_logins"]]
    notes = {"skipped_undated": "line(s) ignored because their timestamp could not be read",
             "malformed": "SSH-looking line(s) that could not be parsed",
             "invalid_ip": "line(s) ignored because the address is not a valid IP",
             "repeated_summaries": "'message repeated N times' line(s) (not expanded, counts may be too low)"}
    out += [f"Note: {s[key]} {text}" for key, text in notes.items() if s[key]]
    return "\n".join(out)


def build_parser():
    p = argparse.ArgumentParser(description="Analyze an OpenSSH auth log for brute-force patterns (read-only).")
    p.add_argument("logfile")
    p.add_argument("-t", "--threshold", type=int, default=5,
                   help="failed logins before an IP is flagged (default: 5)")
    p.add_argument("-w", "--window", type=int,
                   help="count failures only if they fall inside this many seconds")
    p.add_argument("--as-of", type=date.fromisoformat, metavar="YYYY-MM-DD",
                   help="last day the log can contain; only used for syslog timestamps without a year "
                        "(default: today)")
    p.add_argument("--blocklist", help="also write the flagged IPs to this file, one per line")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    return p


def main(argv=None):
    """Exit codes: 0 = analysis finished (findings do not change it), 2 = bad input or I/O error."""
    args = build_parser().parse_args(argv)
    if args.blocklist and same_file(args.logfile, args.blocklist):
        print(f"error: refusing to write the blocklist over the log file {args.logfile}", file=sys.stderr)
        return 2
    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as f:
            result = analyze(f, args.threshold, args.window, args.as_of)
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2) if args.json else format_report(result, args.threshold, args.window))
    if args.blocklist:
        try:
            write_blocklist(args.blocklist, result["suspects"])
        except OSError as exc:
            print(f"error: cannot write blocklist {args.blocklist}: {exc.strerror or exc}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
