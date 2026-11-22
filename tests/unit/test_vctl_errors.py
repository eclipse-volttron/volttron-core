"""vctl's exit codes and messages for a command's failures (control.run_command)."""
import argparse
import io

import pytest

from volttron.client.commands import control
from volttron.utils.jsonrpc import RemoteError


@pytest.fixture
def stderr(monkeypatch):
    """What vctl writes to stderr: control writes to a module-level alias taken at import, so it is replaced here."""
    stream = io.StringIO()
    monkeypatch.setattr(control, "_stderr", stream)
    return stream


class Connection:
    killed = False

    def kill(self):
        self.killed = True


def _opts(func, debug=False):
    return argparse.Namespace(func=func, command="install", timeout=5, debug=debug, connection=Connection())


def _raise(exc):
    def func(opts):
        raise exc
    return func


def test_success_returns_the_commands_result():
    opts = _opts(lambda opts: 0)
    connection = opts.connection
    assert control.run_command(opts, argparse.ArgumentParser()) == 0
    assert connection.killed and opts.connection is None


def test_a_remote_error_prints_its_message(stderr):
    remote = RemoteError("Identity already exists, but not forced!", exc_type="builtins.ValueError")
    assert control.run_command(_opts(_raise(remote)), argparse.ArgumentParser()) == 20
    assert stderr.getvalue() == "install: error: Identity already exists, but not forced!\n"


def test_debug_adds_the_remote_traceback(stderr):
    remote = RemoteError("boom", exc_type="builtins.ValueError", exc_args=["boom"],
                         exc_tb='Traceback (most recent call last):\n  File "aip.py", line 1\nValueError: boom\n')
    assert control.run_command(_opts(_raise(remote), debug=True), argparse.ArgumentParser()) == 20
    assert stderr.getvalue().startswith("install: error: boom\nRemote Traceback")
    assert "aip.py" in stderr.getvalue()


@pytest.mark.parametrize("debug", [False, True])
def test_a_nonzero_exit_returns_20_even_with_debug(stderr, debug):
    assert control.run_command(_opts(_raise(SystemExit(3)), debug=debug), argparse.ArgumentParser()) == 20


@pytest.mark.parametrize("code", [0, None])
def test_a_zero_or_empty_exit_is_success(code):
    assert control.run_command(_opts(_raise(SystemExit(code))), argparse.ArgumentParser()) == 0


def test_a_missing_file_is_reported(stderr):
    assert control.run_command(_opts(_raise(FileNotFoundError("Invalid wheel file x.whl"))),
                               argparse.ArgumentParser()) == 1
    assert stderr.getvalue() == "Invalid wheel file x.whl\n"
