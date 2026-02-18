"""Tests for proxy.sudo — sudo log parsing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from proxy.sudo import _join_sudo_log_lines, _parse_sudo_log_entry, parse_sudo_log


class TestParseSudoLogEntry:
    """Tests for parsing individual sudo log entries."""

    def test_standard_entry(self):
        entry = 'Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/home/runner ; USER=root ; COMMAND=/usr/bin/apt-get install -y curl'
        event = _parse_sudo_log_entry(entry)
        assert event is not None
        assert event["type"] == "sudo"
        assert event["cmdline"] == ["/usr/bin/apt-get", "install", "-y", "curl"]
        assert event["pwd"] == "/home/runner"
        assert event["target_user"] == "root"
        assert "10:30:45" in event["ts"]

    def test_github_runner_format_with_stars(self):
        """On GitHub runners (NOPASSWD, no TTY), some fields are replaced with ***."""
        entry = "Feb 18 00:41:17 : runner : *** ; USER=root ; COMMAND=/usr/bin/whoami"
        event = _parse_sudo_log_entry(entry)
        assert event is not None
        assert event["cmdline"] == ["/usr/bin/whoami"]
        assert event["target_user"] == "root"
        assert "pwd" not in event  # No PWD when *** is used

    def test_single_word_command(self):
        entry = "Jan  5 09:00:00 : runner : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/whoami"
        event = _parse_sudo_log_entry(entry)
        assert event is not None
        assert event["cmdline"] == ["/usr/bin/whoami"]

    def test_command_with_quoted_args(self):
        entry = 'Mar  1 12:00:00 : runner : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c "echo hello world"'
        event = _parse_sudo_log_entry(entry)
        assert event is not None
        assert event["cmdline"] == ["/bin/sh", "-c", "echo hello world"]

    def test_missing_command_field(self):
        entry = "Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/home/runner ; USER=root"
        event = _parse_sudo_log_entry(entry)
        assert event is None

    def test_malformed_entry(self):
        event = _parse_sudo_log_entry("not a sudo log line")
        assert event is None

    def test_empty_entry(self):
        event = _parse_sudo_log_entry("")
        assert event is None

    def test_bad_timestamp(self):
        entry = "notadate : runner : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        event = _parse_sudo_log_entry(entry)
        assert event is None

    def test_no_pwd(self):
        """PWD is optional in our parser output."""
        entry = "Feb 18 10:30:45 : runner : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls"
        event = _parse_sudo_log_entry(entry)
        assert event is not None
        assert "pwd" not in event
        assert event["target_user"] == "root"

    def test_timestamp_is_iso_utc(self):
        entry = "Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        event = _parse_sudo_log_entry(entry)
        assert event["ts"].endswith("+00:00")


class TestJoinSudoLogLines:
    """Tests for joining multiline sudo log entries."""

    def test_single_line_entry(self):
        lines = ["Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n"]
        entries = _join_sudo_log_lines(lines)
        assert len(entries) == 1

    def test_multiline_entry(self):
        lines = [
            "Feb 18 00:41:17 : runner : *** ;\n",
            "    USER=root ; COMMAND=/usr/bin/whoami\n",
        ]
        entries = _join_sudo_log_lines(lines)
        assert len(entries) == 1
        assert "COMMAND=/usr/bin/whoami" in entries[0]
        assert "***" in entries[0]

    def test_multiple_multiline_entries(self):
        lines = [
            "Feb 18 00:41:17 : runner : *** ;\n",
            "    USER=root ; COMMAND=/usr/bin/whoami\n",
            "Feb 18 00:41:18 : runner : *** ;\n",
            "    USER=root ; COMMAND=/usr/bin/ls /root\n",
        ]
        entries = _join_sudo_log_lines(lines)
        assert len(entries) == 2
        assert "whoami" in entries[0]
        assert "/usr/bin/ls" in entries[1]

    def test_skips_empty_lines(self):
        lines = [
            "Feb 18 00:41:17 : runner : *** ;\n",
            "    USER=root ; COMMAND=/bin/ls\n",
            "\n",
            "Feb 18 00:41:18 : runner : *** ;\n",
            "    USER=root ; COMMAND=/bin/whoami\n",
        ]
        entries = _join_sudo_log_lines(lines)
        assert len(entries) == 2

    def test_mixed_single_and_multiline(self):
        lines = [
            "Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n",
            "Feb 18 00:41:17 : runner : *** ;\n",
            "    USER=root ; COMMAND=/bin/whoami\n",
        ]
        entries = _join_sudo_log_lines(lines)
        assert len(entries) == 2


class TestParseSudoLog:
    """Tests for parsing the full sudo log file."""

    def test_nonexistent_file(self, monkeypatch):
        monkeypatch.setattr("proxy.sudo.SUDO_LOG_FILE", "/nonexistent/sudo.log")
        assert parse_sudo_log() == []

    def test_parse_single_line_entries(self, tmp_path):
        import proxy.sudo as sudo_mod

        log_file = tmp_path / "sudo.log"
        log_file.write_text(
            "Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/home/runner ; USER=root ; COMMAND=/usr/bin/apt-get update\n"
            "Feb 18 10:31:00 : runner : TTY=pts/0 ; PWD=/home/runner ; USER=root ; COMMAND=/usr/bin/apt-get install -y curl\n"
        )

        original = sudo_mod.SUDO_LOG_FILE
        sudo_mod.SUDO_LOG_FILE = str(log_file)
        try:
            events = parse_sudo_log()
            assert len(events) == 2
            assert events[0]["cmdline"] == ["/usr/bin/apt-get", "update"]
            assert events[1]["cmdline"] == ["/usr/bin/apt-get", "install", "-y", "curl"]
        finally:
            sudo_mod.SUDO_LOG_FILE = original

    def test_parse_multiline_entries(self, tmp_path):
        """Real GitHub runner format with *** and line wrapping."""
        import proxy.sudo as sudo_mod

        log_file = tmp_path / "sudo.log"
        log_file.write_text(
            "Feb 18 00:41:17 : runner : *** ;\n"
            "    USER=root ; COMMAND=/usr/bin/whoami\n"
            "Feb 18 00:41:17 : runner : *** ;\n"
            "    USER=root ; COMMAND=/usr/bin/ls /root\n"
            "Feb 18 00:41:17 : runner : *** ;\n"
            "    USER=root ; COMMAND=/usr/bin/apt-get update -qq\n"
        )

        original = sudo_mod.SUDO_LOG_FILE
        sudo_mod.SUDO_LOG_FILE = str(log_file)
        try:
            events = parse_sudo_log()
            assert len(events) == 3
            assert events[0]["cmdline"] == ["/usr/bin/whoami"]
            assert events[1]["cmdline"] == ["/usr/bin/ls", "/root"]
            assert events[2]["cmdline"] == ["/usr/bin/apt-get", "update", "-qq"]
        finally:
            sudo_mod.SUDO_LOG_FILE = original

    def test_skips_malformed_lines(self, tmp_path):
        import proxy.sudo as sudo_mod

        log_file = tmp_path / "sudo.log"
        log_file.write_text(
            "garbage line\n"
            "Feb 18 10:30:45 : runner : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n"
            "\n"
        )

        original = sudo_mod.SUDO_LOG_FILE
        sudo_mod.SUDO_LOG_FILE = str(log_file)
        try:
            events = parse_sudo_log()
            assert len(events) == 1
            assert events[0]["cmdline"] == ["/bin/ls"]
        finally:
            sudo_mod.SUDO_LOG_FILE = original
