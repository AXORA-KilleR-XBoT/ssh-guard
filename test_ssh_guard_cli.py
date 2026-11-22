import json
from pathlib import Path

import pytest

from ssh_guard import main, write_blocklist

SAMPLE = str(Path(__file__).with_name("sample_auth.log"))
ARGS = [SAMPLE, "--as-of", "2026-10-10"]


def test_text_report(capsys):
    assert main(ARGS) == 0
    out = capsys.readouterr().out
    assert "203.0.113.7" in out and "192.0.2.44" in out and "198.51.100.9" not in out
    assert "not proof of compromise" in out


def test_json_report(capsys):
    assert main(ARGS + ["--json"]) == 0
    assert set(json.loads(capsys.readouterr().out)) == {"suspects", "suspicious_logins", "stats"}


def test_window_option(capsys):
    assert main(ARGS + ["--window", "30"]) == 0
    assert "within 30s" in capsys.readouterr().out


def test_blocklist_is_sorted_plain_text(tmp_path):
    target = tmp_path / "blocked.txt"
    assert main(ARGS + ["--blocklist", str(target)]) == 0
    assert target.read_text() == "192.0.2.44\n203.0.113.7\n"


def test_blocklist_removes_duplicates_and_sorts_ipv4_before_ipv6(tmp_path):
    target = tmp_path / "b.txt"
    write_blocklist(target, [{"ip": "2001:db8::1"}, {"ip": "203.0.113.7"}, {"ip": "203.0.113.7"}])
    assert target.read_text() == "203.0.113.7\n2001:db8::1\n"


def test_blocklist_write_failure_is_an_error_message_not_a_traceback(tmp_path, capsys):
    assert main(ARGS + ["--blocklist", str(tmp_path)]) == 2     # a directory cannot be written as a file
    assert "cannot write blocklist" in capsys.readouterr().err


def test_blocklist_never_overwrites_the_log_being_read(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(Path(SAMPLE).read_text(encoding="utf-8"), encoding="utf-8")
    before = log.read_bytes()
    assert main([str(log), "--as-of", "2026-10-10", "--blocklist", str(log)]) == 2
    assert "refusing" in capsys.readouterr().err
    assert log.read_bytes() == before


def test_blocklist_never_overwrites_the_log_through_a_symlink(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(Path(SAMPLE).read_text(encoding="utf-8"), encoding="utf-8")
    alias = tmp_path / "alias.txt"
    try:
        alias.symlink_to(log)
    except OSError:
        pytest.skip("symbolic links are not available here")
    before = log.read_bytes()
    assert main([str(log), "--as-of", "2026-10-10", "--blocklist", str(alias)]) == 2
    assert "refusing" in capsys.readouterr().err
    assert log.read_bytes() == before


def test_nothing_is_written_unless_a_blocklist_is_requested(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(ARGS) == 0
    assert list(tmp_path.iterdir()) == []


def test_missing_or_unreadable_logfile(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == 2
    assert main([str(tmp_path)]) == 2                            # a directory is not a log file
    assert capsys.readouterr().err.count("cannot read") == 2


@pytest.mark.parametrize("extra", [["--threshold", "0"], ["--threshold", "-2"], ["--window", "0"]])
def test_invalid_numbers_exit_with_2(extra, capsys):
    assert main(ARGS + extra) == 2
    assert "must be a whole number" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [["--threshold", "abc"], ["--as-of", "yesterday"], ["--bogus"]])
def test_bad_usage_exits_with_2(extra):
    with pytest.raises(SystemExit) as exc:
        main(ARGS + extra)
    assert exc.value.code == 2


def test_window_without_timestamps_is_an_error(tmp_path, capsys):
    log = tmp_path / "cat.log"
    log.write_text("Failed password for root from 203.0.113.7 port 22 ssh2\n")
    assert main([str(log), "--window", "10"]) == 2
    assert "timestamps" in capsys.readouterr().err


def test_binary_garbage_and_empty_files_do_not_crash(tmp_path, capsys):
    garbage = tmp_path / "garbage.log"
    garbage.write_bytes(b"\xff\xfe\x00 not utf-8\n\r\n")
    empty = tmp_path / "empty.log"
    empty.write_text("")
    assert main([str(garbage)]) == 0 and main([str(empty)]) == 0
    assert capsys.readouterr().out.count("Flagged IP addresses (>= 5 failed logins): 0") == 2


# ---------- hostile log content ----------

HOSTILE_USER = "\x1b[2Jroot\u202e\x07"      # a terminal escape sequence, a bidi override and a bell


def write_log(tmp_path, *lines):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(log)


def test_control_characters_in_user_names_never_reach_the_terminal(tmp_path, capsys):
    log = write_log(
        tmp_path,
        f"Oct  5 10:00:00 srv sshd[1]: Failed password for invalid user {HOSTILE_USER} from 203.0.113.7 port 22 ssh2",
        f"Oct  5 10:00:05 srv sshd[1]: Accepted password for {HOSTILE_USER} from 203.0.113.7 port 22 ssh2")
    assert main([log, "--threshold", "1", "--as-of", "2026-10-10"]) == 0
    out = capsys.readouterr().out
    assert all(ch.isprintable() or ch == "\n" for ch in out)
    assert out.count("\\x1b[2Jroot\\u202e\\x07") == 2          # still visible, as harmless text


def test_json_output_keeps_the_real_user_name_and_stays_plain_ascii(tmp_path, capsys):
    log = write_log(
        tmp_path, f"Oct  5 10:00:00 srv sshd[1]: Failed password for {HOSTILE_USER} from 203.0.113.7 port 22 ssh2")
    assert main([log, "--threshold", "1", "--as-of", "2026-10-10", "--json"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["suspects"][0]["top_users"] == [HOSTILE_USER]
    assert all(ch.isprintable() or ch == "\n" for ch in out)


def test_the_blocklist_only_ever_contains_plain_addresses(tmp_path):
    log = write_log(
        tmp_path, "Oct  5 10:00:00 srv sshd[1]: Failed password for root from fe80::1%$(touch${IFS}owned) port 22 ssh2")
    target = tmp_path / "blocked.txt"
    assert main([log, "--threshold", "1", "--as-of", "2026-10-10", "--blocklist", str(target)]) == 0
    assert target.read_text() == "fe80::1\n"
