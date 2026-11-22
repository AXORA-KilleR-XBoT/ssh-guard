# SSH Guard

A small, read-only Python command line tool that reads an OpenSSH authentication log and points out
IP addresses with many failed logins, plus successful logins that happened **after** an address had
already been flagged.

<!-- Placeholders to replace before publishing (search for YOUR):
     - YOUR_GITHUB_USERNAME in the badge below (remove the comment markers after the repository exists)
     - YOUR NAME in LICENSE
[![Python CI](https://github.com/YOUR_GITHUB_USERNAME/ssh-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/ssh-guard/actions/workflows/tests.yml)
-->

> **Scope:** a log-analysis aid for a human reviewer. It is not an intrusion detection system and it
> never blocks anything: it only reads one file and prints a report. Findings are heuristics. A
> flagged address is a lead to investigate, not proof of an attack, and a successful login after
> failures is a signal, not proof of a compromise.

## What problem it solves

Any SSH server that is reachable from the internet collects thousands of failed logins from
automated scanners. Reading `/var/log/auth.log` by eye does not scale. This tool answers three
questions quickly:

1. Which addresses failed at least *N* times (optionally: within *S* seconds)?
2. How many different user names did each one try?
3. Did any flagged address later log in successfully?

## Features

- Counts failed logins per IP address and per user name, with a configurable threshold.
- Optional sliding time window (`--window`) to tell a fast burst from slow background noise.
- Sorts events by timestamp before analysing, so a log that is out of order still gives the right answer.
- Understands classic syslog timestamps (`Oct  5 10:01:01`, no year) and ISO 8601 / RFC 3339 timestamps.
- Reports what it could not use (unparsable lines, invalid addresses, lines without a timestamp) instead of silently ignoring it.
- Text or JSON output, and an optional plain-text list of flagged addresses (`--blocklist`).
- Treats the log as untrusted input (see [Security notes](#security-notes)).
- Standard library only; `pytest` is needed just for the tests.

## How it works

Everything is in one file, `ssh_guard.py`:

```text
log file --> parse_events() --> analyze() --> format_report() / JSON / write_blocklist()
             regex + checks     sort by time,   text for people, JSON for scripts,
             per line           sliding window  a plain list of addresses
```

An address is **flagged** when it reaches the threshold of failed logins (counted inside any window
of `--window` seconds when one is given). A successful login is listed only if its address was
already flagged *at that moment in time*, so a login that happened before the failures is not reported.

## Requirements

- Python 3.10 or newer. The tests were run locally on Python 3.10, 3.11, 3.12 and 3.13.
- Nothing to install to run the tool. `pytest` is needed only to run the tests.

## Quick start

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt      # only needed for the tests
python ssh_guard.py sample_auth.log --threshold 5 --as-of 2026-10-31
```

Windows (PowerShell). These commands were not run while preparing this project:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python ssh_guard.py sample_auth.log --threshold 5 --as-of 2026-10-31
```

`sample_auth.log` is a small hand-written log. Its addresses come from the ranges reserved for
documentation (RFC 5737), so they point at no real machine.

To analyse a real server, copy the log somewhere you can read it (on Debian and Ubuntu it is usually
`/var/log/auth.log`, on Red Hat based systems `/var/log/secure`; the exact place depends on your system)
and pass that file instead.

## Options

| Option | Meaning |
| --- | --- |
| `-t`, `--threshold N` | Failed logins before an address is flagged. Default 5. |
| `-w`, `--window S` | Count only failures that fall inside `S` seconds. Without it, all failures in the file count. |
| `--as-of YYYY-MM-DD` | The last day the log can contain. Only used for syslog timestamps, which have no year. Default: today. |
| `--blocklist FILE` | Also write the flagged addresses to `FILE`, one per line. The tool refuses (exit code 2) if `FILE` is the log file being read. |
| `--json` | Print JSON instead of text. |

Exit codes: `0` the analysis finished (findings do **not** change the code), `2` bad input, for example
an unreadable file or an invalid option value.

## Example output

Real output of the sample file (`--as-of` pins the year so that the result is the same on any day):

```text
$ python ssh_guard.py sample_auth.log --threshold 5 --as-of 2026-10-31
Read 14 lines: 12 failed and 2 accepted SSH logins (ordered by timestamp)
Flagged IP addresses (>= 5 failed logins): 2
  192.0.2.44           6 failures, 2026-10-05 10:07:30 to 2026-10-05 10:07:40; 4 user names tried, e.g. oracle, pi, ubuntu
  203.0.113.7          5 failures, 2026-10-05 10:01:01 to 2026-10-05 10:01:09; 3 user names tried, e.g. root, admin, test
Successful logins from flagged IPs (a signal worth investigating, not proof of compromise):
  2026-10-05 10:01:11  root from 203.0.113.7
```

`198.51.100.9` (one typo, then a successful login) is correctly not flagged. With a time window:

```text
$ python ssh_guard.py sample_auth.log --threshold 5 --window 60 --as-of 2026-10-31
Read 14 lines: 12 failed and 2 accepted SSH logins (ordered by timestamp)
Flagged IP addresses (>= 5 failed logins within 60s): 2
  192.0.2.44           6 failures, peak 6 in 60s, 2026-10-05 10:07:30 to 2026-10-05 10:07:40; 4 user names tried, e.g. oracle, pi, ubuntu
  203.0.113.7          5 failures, peak 5 in 60s, 2026-10-05 10:01:01 to 2026-10-05 10:01:09; 3 user names tried, e.g. root, admin, test
Successful logins from flagged IPs (a signal worth investigating, not proof of compromise):
  2026-10-05 10:01:11  root from 203.0.113.7
```

When some lines cannot be used, the report says so (a different, tiny log):

```text
Note: 1 line(s) ignored because the address is not a valid IP
Note: 1 'message repeated N times' line(s) (not expanded, counts may be too low)
```

`--json` prints the same findings for scripts. Shortened real output (`...` marks removed lines):

```text
$ python ssh_guard.py sample_auth.log --threshold 5 --as-of 2026-10-31 --json
{
  "suspects": [
    { "ip": "192.0.2.44", "failures": 6, "peak_in_window": null,
      "first_seen": "2026-10-05 10:07:30", "last_seen": "2026-10-05 10:07:40",
      "distinct_users": 4, "top_users": ["oracle", "pi", "ubuntu"] },
    ...
  ],
  "suspicious_logins": [ { "ip": "203.0.113.7", "user": "root", "time": "2026-10-05 10:01:11" } ],
  "stats": { "lines": 14, "failed": 12, "accepted": 2, "malformed": 0, "invalid_ip": 0,
             "repeated_summaries": 0, "skipped_undated": 0, "mode": "dated" }
}
```

(The real output is pretty-printed over more lines; it is condensed here.)

## Log formats

Recognised lines look like this (OpenSSH message text, `sshd` or `sshd-session` as the program name):

```text
Oct  5 10:01:01 srv sshd[1001]: Failed password for invalid user admin from 203.0.113.7 port 50130 ssh2
2026-10-05T10:01:01+00:00 srv sshd-session[1001]: Accepted publickey for alice from 198.51.100.9 port 40007 ssh2: ED25519 SHA256:...
```

- Every `Failed <method> for ...` line counts as one failure (password, publickey, keyboard-interactive, ...).
- `Accepted <method> for ...` lines are the successful logins.
- Timestamps with a UTC offset are converted to UTC. Classic syslog timestamps have no time zone and
  no year: the newest year that is not after `--as-of` is used (this also makes a log that crosses
  New Year work). Do not mix both styles in one file, because they are not on the same clock.
- Lines without a readable timestamp are skipped and counted. If **no** line has a timestamp, file order
  is used and `--window` is refused (it cannot work without times).
- The fixtures in this repository are hand-written from the OpenSSH message format. The tool was
  **not** tested against real logs from different distributions or OpenSSH versions.

## Tests and CI

```bash
python -m pytest -q
```

The tests cover: time-window boundaries (a span of exactly the window still counts), out-of-order lines,
year boundaries, malformed and oversized lines, invalid and look-alike addresses, user names that try to
spoof the parser, threshold edge cases, blocklist and file errors, and hostile input (terminal escape
sequences and odd IPv6 scope text).

`.github/workflows/tests.yml` runs the tests on Python 3.10 to 3.13 for pushes to `main`, pull requests and
manual runs, then runs the command line once on the sample file. It has read-only repository permissions,
and the actions it uses are pinned to full commit SHAs.

## Security notes

- The tool opens the log read-only. It runs no commands, makes no network connections, and **never
  blocks anything**. `--blocklist` only writes a text file of addresses, and refuses to overwrite the log it is reading.
- **Review the list before you use it anywhere.** An address can be shared by many people (an office, a
  mobile network, a VPN) or be your own, and blocking it can lock out legitimate users or yourself.
- The log is treated as untrusted. User names in log lines are chosen by whoever tried to log in, so:
  the user name is matched up to the final `from <ip> port <n>`, which means a user name that contains
  fake log text cannot change which address is blamed; control and invisible characters in user names are
  escaped in the text report; IPv6 scope text such as `fe80::1%eth0` is dropped, so only plain addresses
  reach the report and the blocklist; and lines longer than 4096 characters are counted as malformed.
- Memory use grows with the number of authentication events in the file. It was not measured on
  very large logs.

## Limitations

- OpenSSH only. Other SSH servers (for example Dropbear) and logs with a different layout are not recognised.
- Only `Failed ...` and `Accepted ...` result lines are used. Pre-authentication lines such as
  `Invalid user ...`, `Connection closed by authenticating user ...` or `Timeout before authentication`
  are not counted, so very quick scanners may be undercounted.
- rsyslog `message repeated N times: [...]` summary lines are reported but not expanded, so counts can be too low.
- Detection is per address. Many addresses that each stay below the threshold (a distributed or "low and
  slow" attack) are not detected, and nothing correlates one user name across addresses.
- Addresses are not looked up, geolocated or checked against any reputation list.

## Roadmap

Real work that is still open:

- Test against real, anonymised logs from several distributions and OpenSSH versions.
- Expand `message repeated N times` lines.
- Optional exit code when something is flagged (for use in scripts).
- An allowlist of trusted addresses, so your own networks are never flagged.
- Reading very large logs without keeping every event in memory.
- Run the tests and the command line on Windows and publish the result.

## License

MIT, see `LICENSE`. The copyright holder in that file is a placeholder (`YOUR NAME`): replace it
with your own name before publishing.
