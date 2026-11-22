"""The server's command line and config file, as parse_server_args reads them (volttron-core#306).

These record today's behaviour so the replacement of the subclassed argparse can be checked against it. Where the
replacement is meant to change something, the test says so.
"""
import pytest

from volttron.server.run_server import parse_server_args
from volttron.server.server_options import ServerOptions

CONFIG = "[volttron]\ninstance-name = fromconfig\naddress = tcp://127.0.0.1:1111\n"


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "volttron_home"
    home.mkdir()
    (home / "platform-lookup.key").write_text("secret\n")    # federation needs a password file
    (home / "platform-lookup.key").chmod(0o600)
    monkeypatch.setenv("VOLTTRON_HOME", str(home))
    monkeypatch.delenv("SKIP_VOLTTRON_CONFIG", raising=False)
    return home


def parse(home, args=(), config=None):
    cfg = home / "config"
    if config is not None:
        cfg.write_text(config)
    options = ServerOptions(config_file=cfg) if cfg.exists() else ServerOptions(volttron_home=home)
    return parse_server_args(list(args), options, home)


@pytest.mark.parametrize("args, level", [
    ([], 30), (["-v"], 20), (["-vv"], 10), (["-vvq"], 20), (["-q"], 40), (["--verboseness", "10"], 10),
])
def test_verbosity(home, args, level):
    assert parse(home, args).verboseness == level


@pytest.mark.parametrize("args", [["-l", "X"], ["-lX"], ["--log=X"], ["--log", "X"]])
def test_every_log_form_parses(home, args):
    assert parse(home, args).log == "X"


def test_monitor_and_its_abbreviation(home):
    # The server parser accepts abbreviations; vctl's does not.
    assert parse(home, ["--monitor"]).monitor and parse(home, ["--mon"]).monitor


def test_config_file_values_are_used(home):
    opts = parse(home, config=CONFIG)
    assert opts.instance_name == "fromconfig"
    assert list(dict.fromkeys(opts.address)) == ["tcp://127.0.0.1:1111"]


def test_command_line_wins_for_single_values(home):
    assert parse(home, ["--instance-name", "cli"], config=CONFIG).instance_name == "cli"


def test_command_line_addresses_are_added_to_the_config_addresses(home):
    # Combined, config first (volttron-core#372 proposes replacing instead). Today the config's address appears
    # twice; ServerOptions.update() removes the duplicate.
    opts = parse(home, ["--address", "tcp://127.0.0.1:2222"], config=CONFIG)
    assert list(dict.fromkeys(opts.address)) == ["tcp://127.0.0.1:1111", "tcp://127.0.0.1:2222"]


@pytest.mark.parametrize("value, expected", [("True", True), ("False", False)])
def test_config_booleans(home, value, expected):
    opts = parse(home, config=f"[volttron]\nenable-federation = {value}\nautostart = {value}\n")
    assert opts.enable_federation is expected and opts.autostart is expected


def test_boolean_flags_override_the_config(home):
    opts = parse(home, ["--disable-federation", "--no-autostart"],
                 config="[volttron]\nenable-federation = True\nautostart = True\n")
    assert opts.enable_federation is False and opts.autostart is False


def test_unknown_config_key_stops_with_file_and_key(home, capsys):
    with pytest.raises(SystemExit) as exit:
        parse(home, config="[volttron]\nnot-a-key = 1\n")
    assert exit.value.code == 2
    err = capsys.readouterr().err
    assert str(home / "config") in err and "unknown option: not-a-key" in err


def test_other_sections_are_ignored(home):
    opts = parse(home, config="[volttron]\ninstance-name = a\n[web]\nbind-web-address = http://127.0.0.1:1\n")
    assert opts.instance_name == "a" and not hasattr(opts, "bind_web_address")


def test_explicit_config_file(home):
    other = home / "other.cfg"
    other.write_text("[volttron]\ninstance-name = viaflag\n")
    assert parse(home, ["-c", str(other)]).instance_name == "viaflag"


def test_skip_volttron_config_skips_only_the_parser_pass(home, monkeypatch):
    # ServerOptions still reads the file, so its values remain the defaults.
    monkeypatch.setenv("SKIP_VOLTTRON_CONFIG", "1")
    assert parse(home, config=CONFIG).instance_name == "fromconfig"


def test_agent_isolation_mode_from_the_command_line_or_config(home):
    assert parse(home, ["--agent-isolation-mode", "True"]).agent_isolation_mode is True
    assert parse(home, config="[volttron]\nagent-isolation-mode = False\n").agent_isolation_mode is False


def test_agent_isolation_mode_is_off_by_default(home):
    # volttron-core#373: the boolean default used to be compared with the string 'False'.
    assert parse(home).agent_isolation_mode is False


@pytest.mark.parametrize("flag", ["--help", "--version"])
def test_help_and_version_exit_cleanly(home, flag, capsys):
    with pytest.raises(SystemExit) as exit:
        parse(home, [flag])
    assert exit.value.code == 0
    assert capsys.readouterr().out
