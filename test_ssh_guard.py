import random
from datetime import date, datetime
from pathlib import Path

import pytest

from ssh_guard import analyze

SAMPLE = Path(__file__).with_name("sample_auth.log")
AS_OF = date(2026, 10, 10)


def failed(ip="203.0.113.7", user="root", ts="Oct  5 10:00:00", method="password", invalid=False):
    who = f"invalid user {user}" if invalid else user
    return f"{ts} srv sshd[100]: Failed {method} for {who} from {ip} port 4242 ssh2"


def accepted(ip="203.0.113.7", user="root", ts="Oct  5 10:30:00", method="password"):
    return f"{ts} srv sshd[101]: Accepted {method} for {user} from {ip} port 4242 ssh2"


def at(seconds):
    """An RFC 3339 timestamp `seconds` after 2026-10-05 10:00:00 UTC (keep it below 3600)."""
    return f"2026-10-05T10:{seconds // 60:02d}:{seconds % 60:02d}+00:00"


def burst(n, ip="203.0.113.7", start=0, step=1):
    return [failed(ip, ts=at(start + i * step)) for i in range(n)]


def run(lines, **options):
    options.setdefault("as_of", AS_OF)
    return analyze(lines, **options)


def flagged(result):
    return [s["ip"] for s in result["suspects"]]


# ---------- counting, thresholds, windows ----------

def test_sample_log():
    result = run(SAMPLE.read_text().splitlines())
    assert {s["ip"]: s["failures"] for s in result["suspects"]} == {"203.0.113.7": 5, "192.0.2.44": 6}
    assert result["suspicious_logins"] == [{"ip": "203.0.113.7", "user": "root", "time": "2026-10-05 10:01:11"}]
    assert result["stats"]["failed"] == 12 and result["stats"]["accepted"] == 2


@pytest.mark.parametrize("count, threshold, expected", [
    (4, 5, []), (5, 5, ["203.0.113.7"]), (6, 5, ["203.0.113.7"]), (1, 1, ["203.0.113.7"]), (1, 2, []),
])
def test_threshold_edges(count, threshold, expected):
    assert flagged(run(burst(count), threshold=threshold)) == expected


def test_window_boundary_is_inclusive():
    exactly_60s = [failed(ts=at(s)) for s in (0, 15, 30, 45, 60)]
    assert flagged(run(exactly_60s, window=60)) == ["203.0.113.7"]
    just_over = [failed(ts=at(s)) for s in (0, 15, 30, 45, 61)]
    assert flagged(run(just_over, window=60)) == []


def test_slow_attack_is_not_a_burst_and_counts_stay_consistent():
    slow = [failed(ts=at(s)) for s in (0, 600, 1200, 1800, 2400)]
    assert flagged(run(slow)) == ["203.0.113.7"]            # 5 failures over the whole log
    assert flagged(run(slow, window=60)) == []              # but never 5 inside one minute
    suspect = run(slow, threshold=1, window=60)["suspects"][0]
    assert suspect["failures"] == 5                         # total is always the whole-log count
    assert suspect["peak_in_window"] == 1                   # the window result is reported separately
    assert run(slow)["suspects"][0]["peak_in_window"] is None


def test_identical_repeated_lines_each_count():
    assert run([failed()] * 7, threshold=1)["suspects"][0]["failures"] == 7


def test_user_names_are_summarized():
    lines = [failed(user=u, ts=at(i)) for i, u in enumerate(["a", "a", "b", "c", "d"])]
    suspect = run(lines, threshold=1)["suspects"][0]
    assert suspect["distinct_users"] == 4 and suspect["top_users"][0] == "a"


# ---------- ordering, missing timestamps, years ----------

def test_out_of_order_lines_give_the_same_result():
    lines = burst(6) + [accepted(ts=at(120))]
    expected = run(lines, window=10)
    assert flagged(expected) == ["203.0.113.7"] and len(expected["suspicious_logins"]) == 1
    for seed in range(5):
        shuffled = lines[:]
        random.Random(seed).shuffle(shuffled)
        assert run(shuffled, window=10) == expected


def test_login_is_judged_by_time_not_by_position_in_the_file():
    failures = burst(5, start=600)       # 10:10:00 - 10:10:04
    earlier_login = accepted(ts=at(0))   # 10:00:00, before the burst
    later_login = accepted(ts=at(1200))  # 10:20:00, after the burst
    result = run([later_login] + failures + [earlier_login])   # listed in the "wrong" order on purpose
    assert [x["time"] for x in result["suspicious_logins"]] == ["2026-10-05 10:20:00"]


def test_lines_without_a_readable_timestamp_are_skipped_and_reported():
    undated = "garbage srv sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2"
    result = run(burst(4) + [undated])
    assert flagged(result) == []                    # 4 dated failures + 1 undated one is NOT 5
    assert result["stats"]["skipped_undated"] == 1


def test_impossible_calendar_values_count_as_missing_timestamps():
    lines = burst(1) + [failed(ts="Oct 32 10:00:00"), failed(ts="Oct  5 25:61:00"), failed(ts="Foo  5 10:00:00")]
    assert run(lines)["stats"]["skipped_undated"] == 3


def test_impossible_iso_timestamps_count_as_missing_timestamps():
    lines = burst(1) + [
        failed(ts="2026-13-45T10:00:00+00:00"),       # no such month
        failed(ts="2026-10-05T25:00:00+00:00"),       # no such hour
        failed(ts="0001-01-01T00:00:00+05:00"),       # converting to UTC would leave the supported dates
    ]
    assert run(lines)["stats"]["skipped_undated"] == 3


def test_as_of_may_also_be_a_datetime():
    """The year of a syslog timestamp is the newest one that is not after the moment given."""
    line = failed(ts="Oct  7 10:00:00")
    assert run([line], threshold=1, as_of=datetime(2026, 10, 7, 9, 59, 59))["suspects"][0]["first_seen"] == "2025-10-07 10:00:00"
    assert run([line], threshold=1, as_of=datetime(2026, 10, 7, 10, 0, 0))["suspects"][0]["first_seen"] == "2026-10-07 10:00:00"


def test_log_without_any_timestamps_uses_file_order():
    # For example the output of `journalctl -u ssh -o cat`.
    lines = ["Failed password for root from 203.0.113.7 port 22 ssh2"] * 5 + [
        "Accepted password for root from 203.0.113.7 port 22 ssh2"]
    result = run(lines)
    assert flagged(result) == ["203.0.113.7"] and result["stats"]["mode"] == "undated"
    assert result["suspicious_logins"][0]["time"] is None
    with pytest.raises(ValueError, match="timestamps"):
        run(lines, window=30)
    assert run([], window=30)["suspects"] == []     # an empty log is not an error


def test_new_year_boundary_with_syslog_timestamps():
    lines = [failed(ts=f"Dec 31 23:59:{s}") for s in (56, 57, 58, 59)] + [failed(ts="Jan  1 00:00:02")]
    result = run(lines, window=10, as_of=date(2026, 1, 3))
    assert flagged(result) == ["203.0.113.7"]
    suspect = result["suspects"][0]
    assert suspect["first_seen"] == "2025-12-31 23:59:56" and suspect["last_seen"] == "2026-01-01 00:00:02"


def test_syslog_year_is_the_newest_year_not_after_as_of():
    assert run([failed(ts="Dec 25 08:00:00")], threshold=1)["suspects"][0]["first_seen"] == "2025-12-25 08:00:00"
    leap = run([failed(ts="Feb 29 12:00:00")], threshold=1, as_of=date(2025, 3, 1))
    assert leap["suspects"][0]["first_seen"] == "2024-02-29 12:00:00"   # 2025 has no Feb 29


@pytest.mark.parametrize("a, b", [
    ("2026-10-05T10:00:00+00:00", "2026-10-05T13:30:00+03:30"),
    ("2026-10-05T10:00:00Z", "2026-10-05T05:00:00-05:00"),
    ("2026-10-05T10:00:00.123456+0000", "2026-10-05 10:00:00"),
])
def test_rfc3339_offsets_are_converted_to_one_timeline(a, b):
    suspect = run([failed(ts=a), failed(ts=b)], threshold=2, window=1)["suspects"][0]
    assert suspect["first_seen"] == suspect["last_seen"] == "2026-10-05 10:00:00"


# ---------- parser: formats, malformed lines, spoofing ----------

@pytest.mark.parametrize("method", ["password", "publickey", "keyboard-interactive/pam", "none", "gssapi-with-mic"])
def test_authentication_methods(method):
    assert flagged(run([failed(method=method)], threshold=1)) == ["203.0.113.7"]


def test_sshd_session_tag_and_invalid_user_prefix():
    line = "2026-10-05T10:00:00+00:00 srv sshd-session[7]: Failed password for invalid user admin from 203.0.113.7 port 1 ssh2"
    suspect = run([line], threshold=1)["suspects"][0]
    assert suspect["top_users"] == ["admin"]


def test_only_failed_and_accepted_results_are_counted():
    lines = [
        "Oct  5 10:00:00 srv sshd[1]: Invalid user admin from 203.0.113.7 port 22",
        "Oct  5 10:00:00 srv sshd[1]: Connection closed by authenticating user root 203.0.113.7 port 22 [preauth]",
        "Oct  5 10:00:00 srv sudo: Failed password for root from 203.0.113.7 port 22 ssh2",
        "Oct  5 10:00:00 srv sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=203.0.113.7",
    ]
    result = run(lines, threshold=1)
    assert result["suspects"] == [] and result["stats"]["failed"] == 0


@pytest.mark.parametrize("line", [
    "",
    "just some text",
    "\x00\x01\x02 binary \xff junk",
    "Oct  5 10:00:00 srv sshd[1]: Accepted",
    "Oct  5 10:00:00 srv sshd[1]: Failed password for from 203.0.113.7 port 22 ssh2",
    "Oct  5 10:00:00 srv sshd[1]: Failed password root from 203.0.113.7 port 22",
])
def test_malformed_lines_are_ignored_without_crashing(line):
    result = run([line], threshold=1)
    assert result["suspects"] == [] and result["stats"]["failed"] == 0 and result["stats"]["accepted"] == 0


def test_malformed_ssh_lines_are_counted():
    lines = [
        "Oct  5 10:00:00 srv sshd[1]: Failed password for root from 203.0.113.7",             # no port
        "Oct  5 10:00:00 srv sshd[1]: Failed password for root from 203.0.113.7 port abc ssh2",
        "x" * 5000,                                                                           # over the line limit
    ]
    assert run(lines)["stats"]["malformed"] == 3


def test_user_names_with_spaces_and_fake_log_text_do_not_fool_the_parser():
    spoof = ("Oct  5 10:00:00 srv sshd[1]: Failed password for invalid user evil from 10.9.9.9 port 1 "
             "from 203.0.113.9 port 4444 ssh2")
    result = run([spoof, failed(user="john smith", invalid=True)], threshold=1)
    assert sorted(flagged(result)) == ["203.0.113.7", "203.0.113.9"]    # 10.9.9.9 is NOT blamed
    assert {s["ip"]: s["top_users"] for s in result["suspects"]}["203.0.113.7"] == ["john smith"]


def test_rsyslog_repeat_summaries_are_reported_not_expanded():
    line = ("Oct  5 10:00:00 srv sshd[1]: message repeated 5 times: "
            "[ Failed password for root from 203.0.113.7 port 22 ssh2]")
    result = run([line], threshold=1)
    assert result["suspects"] == [] and result["stats"]["repeated_summaries"] == 1


# ---------- IP addresses ----------

def test_ip_addresses_are_normalized_before_counting():
    lines = [failed(ip="2001:db8:0:0:0:0:0:1"), failed(ip="2001:db8::1"),
             failed(ip="::ffff:203.0.113.7"), failed(ip="203.0.113.7")]
    result = run(lines, threshold=2)
    assert {s["ip"]: s["failures"] for s in result["suspects"]} == {"2001:db8::1": 2, "203.0.113.7": 2}


@pytest.mark.parametrize("bad_ip", ["999.1.1.1", "1.2.3", "01.2.3.4", "1.2.3.4.5", "example.com", "gggg::1",
                                    "203.0.113.7/24", "-"])
def test_invalid_addresses_are_skipped_and_counted(bad_ip):
    result = run([failed(ip=bad_ip)], threshold=1)
    assert result["suspects"] == [] and result["stats"]["invalid_ip"] == 1


def test_a_valid_address_with_the_same_line_shape_is_flagged():
    assert flagged(run([failed(ip="203.0.113.9")], threshold=1)) == ["203.0.113.9"]


def test_ipv6_scope_ids_are_dropped_so_one_host_is_counted_once():
    lines = [failed(ip="fe80::1%eth0"), failed(ip="fe80::1%wlan0"), failed(ip="fe80::1")]
    result = run(lines, threshold=3)
    assert {s["ip"]: s["failures"] for s in result["suspects"]} == {"fe80::1": 3}


@pytest.mark.parametrize("scope", ["\x1b[2J", "$(reboot)", ";rm", "`id`", "\u202e", "a\x07"])
def test_text_after_the_percent_sign_never_reaches_the_results(scope):
    """Python's ipaddress accepts ANY text as an IPv6 scope id, so it must not be passed on."""
    result = run([failed(ip=f"fe80::1%{scope}")], threshold=1)
    assert flagged(result) == ["fe80::1"]


# ---------- wording and option validation ----------

def test_successful_login_after_flagging_is_only_a_signal():
    lines = burst(5) + [accepted(ts=at(100)), accepted(ip="198.51.100.9", ts=at(100))]
    result = run(lines, window=10)
    assert result["suspicious_logins"] == [{"ip": "203.0.113.7", "user": "root", "time": "2026-10-05 10:01:40"}]
    assert "possible_breaches" not in result      # the tool does not claim a breach


@pytest.mark.parametrize("options", [
    {"threshold": 0}, {"threshold": -3}, {"threshold": 2.5}, {"threshold": "5"}, {"threshold": True},
    {"threshold": None}, {"window": 0}, {"window": -1}, {"window": 1.5}, {"window": "10"},
])
def test_invalid_options_raise_value_error(options):
    with pytest.raises(ValueError):
        run([], **options)
