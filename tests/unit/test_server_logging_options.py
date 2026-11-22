"""Server logging is configured once, from the parsed options with the config file included (volttron-core#362).

Before, a hand-written scan of sys.argv in volttron.server.__main__ recognised only ``-l PATH`` and ``-v``, and the
argparse-based setup in run_server never ran because a handler already existed, so every other form was ignored.
"""
import logging

import pytest

from volttron.server import logs
from volttron.server.run_server import configure_server_logging, parse_server_args
from volttron.server.server_options import ServerOptions


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "volttron_home"
    home.mkdir()
    monkeypatch.setenv("VOLTTRON_HOME", str(home))
    monkeypatch.delenv("SKIP_VOLTTRON_CONFIG", raising=False)
    return home


@pytest.fixture(autouse=True)
def clean_logging(monkeypatch):
    """Each test starts with an unconfigured root logger and gets the previous state back. pytest's own capture
    handlers on the root logger do not count as configured logging."""
    from volttron.server import run_server
    monkeypatch.setattr(run_server, "logging_configured", lambda: any(
        not isinstance(h, logs.EarlyLogBuffer) and "LogCapture" not in type(h).__name__
        for h in logging.getLogger().handlers))
    root = logging.getLogger()
    saved = (root.handlers[:], root.level)
    root.handlers[:] = []
    yield
    for handler in root.handlers:
        handler.close()
    root.handlers[:] = saved[0]
    root.setLevel(saved[1])


def configure(home, args=(), config=None):
    if config is not None:
        (home / "config").write_text(config)
    cfg = home / "config"
    options = ServerOptions(config_file=cfg) if cfg.exists() else ServerOptions(volttron_home=home)
    opts = parse_server_args(list(args), options, home)
    configure_server_logging(opts)
    return logging.getLogger()


def file_handler(root):
    files = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
    assert len(files) == 1, root.handlers
    return files[0]


@pytest.mark.parametrize("form", ["-l {}", "-l{}", "--log={}", "--log {}"])
def test_every_log_option_form_writes_the_file(home, tmp_path, form):
    path = tmp_path / "out.log"
    root = configure(home, form.format(path).split(" "))
    assert file_handler(root).baseFilename == str(path)


def test_log_from_the_config_file(home, tmp_path):
    path = tmp_path / "from-config.log"
    root = configure(home, config=f"[volttron]\nlog = {path}\n")
    assert file_handler(root).baseFilename == str(path)


@pytest.mark.parametrize("args, level", [
    ([], logging.WARNING), (["-vv"], logging.DEBUG), (["--verboseness", "10"], logging.DEBUG),
    (["--monitor"], logging.INFO), (["-vv", "-q", "-q"], logging.WARNING), (["-q"], logging.ERROR),
])
def test_level_follows_every_verbosity_option(home, args, level):
    assert configure(home, args).level == level


def test_verbosity_from_the_config_file(home):
    assert configure(home, config="[volttron]\nverboseness = 10\n").level == logging.DEBUG


def test_records_logged_before_configuration_are_replayed_at_the_configured_level(home, tmp_path):
    logs.install_early_log_buffer()
    early = logging.getLogger("volttron.test.early")
    early.debug("early debug")
    early.warning("early warning")
    path = tmp_path / "out.log"
    configure(home, ["-l", str(path)])    # WARNING
    text = path.read_text()
    assert "early warning" in text and "early debug" not in text
    assert logs.early_log_buffer() is None


def test_log_config_excludes_verbosity_and_log(home, tmp_path):
    conf = tmp_path / "logging.ini"
    conf.write_text("[loggers]\nkeys=root\n")
    for args in (["-L", str(conf), "-v"], ["-L", str(conf), "-l", str(tmp_path / "x.log")]):
        with pytest.raises(SystemExit) as exit:
            configure(home, args)
        assert exit.value.code == 2
