"""vctl install keeps stdout for its result (#364): progress messages go to stderr, so --json output parses."""
import argparse
from unittest.mock import MagicMock, patch

import pytest

from volttron.client.commands import install_parser


def _opts(install_path, address="ipc://@/tmp/home/run/vip.socket"):
    opts = argparse.Namespace(install_path=str(install_path), json=True)
    opts.connection = MagicMock()
    opts.connection.address = address
    return opts


@pytest.mark.parametrize("kind", ["editable", "wheel", "pypi"])
def test_progress_messages_go_to_stderr(tmp_path, capsys, kind):
    if kind == "editable":
        path = tmp_path / "agent"
        path.mkdir()
    elif kind == "wheel":
        path = tmp_path / "agent-0.1.0-py3-none-any.whl"
        path.write_bytes(b"")
    else:
        path = "volttron-listener"
    with patch.object(install_parser, "_install_and_initialize_agent") as install:
        install_parser.install_agent_vctl(_opts(path))
    out, err = capsys.readouterr()
    assert install.called
    assert out == ""
    assert "Installing" in err


def test_build_message_goes_to_stderr(tmp_path, capsys):
    path = tmp_path / "agent"
    path.mkdir()
    wheel = tmp_path / "agent-0.1.0-py3-none-any.whl"
    with patch.object(install_parser, "_build_from_pyproject", return_value=wheel) as build, \
            patch.object(install_parser, "_install_and_initialize_agent"), \
            patch("pathlib.Path.is_file", return_value=True):
        install_parser.install_agent_vctl(_opts(path, address="tcp://127.0.0.1:22916"))
    out, err = capsys.readouterr()
    assert build.called
    assert out == ""
    assert "Building agent from" in err and "Installing from wheel" in err
