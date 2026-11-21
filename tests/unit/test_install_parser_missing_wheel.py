"""vctl install of a .whl path that does not exist fails with a clear error instead of going to PyPI (#365)."""
import argparse
from unittest.mock import MagicMock, patch

import pytest

from volttron.client.commands import install_parser


def _opts(install_path):
    opts = argparse.Namespace(install_path=str(install_path), json=True)
    opts.connection = MagicMock()
    opts.connection.address = "ipc://@/tmp/home/run/vip.socket"
    return opts


def test_missing_wheel_is_reported_not_installed_from_pypi(tmp_path):
    missing = tmp_path / "foo" / "wheel.whl"
    with patch.object(install_parser, "_install_and_initialize_agent") as install:
        with pytest.raises(FileNotFoundError, match=f"Invalid wheel file {missing}"):
            install_parser.install_agent_vctl(_opts(missing))
    assert not install.called


def test_package_names_still_go_to_pypi():
    with patch.object(install_parser, "_install_and_initialize_agent") as install:
        install_parser.install_agent_vctl(_opts("volttron-listener"))
    assert install.call_args.kwargs == {"pypi_string": "volttron-listener"}
