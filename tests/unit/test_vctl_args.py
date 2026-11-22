"""vctl's command line, as build_parser reads it (volttron-core#306).

These record today's behaviour so the replacement of the subclassed argparse can be checked against it.
"""
import pytest

from volttron.client.commands.control import build_parser, parse_args


class Vctl:
    """vctl's parser, parsed the way vctl's main does (control.parse_args supplies the global defaults)."""

    def __init__(self, parser):
        self.parser = parser

    def parse_args(self, args):
        return parse_args(self.parser, args)


@pytest.fixture
def parser(tmp_path, monkeypatch):
    monkeypatch.setenv("VOLTTRON_HOME", str(tmp_path))
    return Vctl(build_parser(str(tmp_path)))


def test_defaults(parser):
    opts = parser.parse_args(["status"])
    assert opts.command == "status" and opts.func.__name__ == "status_agents"
    assert opts.timeout == 120.0 and opts.json is False and opts.verboseness == 30


@pytest.mark.parametrize("args", [["-t", "5", "status"], ["status", "-t", "5"]])
def test_global_option_before_or_after_the_command(parser, args):
    assert parser.parse_args(args).timeout == 5.0


def test_verbosity_combines(parser):
    assert parser.parse_args(["-vvq", "status"]).verboseness == 20


def test_json_is_a_top_level_option(parser, capsys):
    assert parser.parse_args(["--json", "status"]).json is True
    with pytest.raises(SystemExit) as exit:
        parser.parse_args(["status", "--json"])
    assert exit.value.code == 2


@pytest.mark.parametrize("args", [["--json", "install", "x"], ["install", "x", "--json"]])
def test_install_json_in_either_place(parser, args):
    opts = parser.parse_args(args)
    assert opts.json is True and opts.func.__name__ == "install_agent_vctl"


def test_install_json_defaults_off(parser):
    assert parser.parse_args(["install", "x"]).json is False


def test_abbreviations_are_rejected(parser):
    with pytest.raises(SystemExit) as exit:
        parser.parse_args(["--tim", "5", "status"])
    assert exit.value.code == 2


def test_errors_print_the_message_then_the_full_help(parser, capsys):
    with pytest.raises(SystemExit) as exit:
        parser.parse_args(["nosuchcmd"])
    assert exit.value.code == 2
    out = capsys.readouterr()
    assert out.err.startswith("error:") and "invalid choice: 'nosuchcmd'" in out.err
    assert "usage:" in out.out and "commands:" in out.out


def test_core_commands_are_registered(parser):
    commands = set(parser.parser._subparsers._group_actions[0].choices)
    assert {"status", "install", "start", "stop", "config", "rpc", "publish", "subscribe", "shutdown"} <= commands
