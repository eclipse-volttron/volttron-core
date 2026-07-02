#!/usr/bin/env python3
"""
Tests for vctl behavior when no optional vctl plugins are installed.

This module simulates an environment where the auth-related plugin package is
not available on ``sys.path``. The tests verify that importing the optional
namespace fails cleanly, that the plugin registry remains empty, and that the
control flow can continue gracefully when the namespace is missing.
"""

import importlib
import sys

import pytest


def _path_without_auth_plugins(path_entries):
    """
    Return a copy of ``sys.path`` with auth plugin locations removed.

    Parameters
    ----------
    path_entries : list[str]
        Original Python import path entries.

    Returns
    -------
    list[str]
        A filtered path list with any entry containing ``volttron-lib-auth``
        removed.
    """
    return [p for p in path_entries if "volttron-lib-auth" not in p]


def _clear_vctl_modules():
    """
    Remove cached vctl plugin modules from ``sys.modules``.

    This prevents prior imports in the current pytest session from affecting
    tests that are specifically checking missing-plugin behavior.
    """
    for name in list(sys.modules):
        if (
            name == "volttron.plugins.vctl"
            or name.startswith("volttron.plugins.vctl.")
        ):
            sys.modules.pop(name, None)


@pytest.fixture
def no_auth_plugin_path(monkeypatch):
    """
    Configure the test environment to behave as if auth plugins are absent.

    The fixture removes any auth-plugin-related paths from ``sys.path`` and
    clears cached vctl namespace modules so each test starts from a clean
    import state.
    """
    monkeypatch.setattr(sys, "path", _path_without_auth_plugins(sys.path.copy()))
    _clear_vctl_modules()


def test_import_vctl_raises_when_no_plugins_installed(no_auth_plugin_path):
    """
    Verify that the optional ``volttron.plugins.vctl`` namespace is missing.

    When the auth plugin package is not installed, importing the vctl plugin
    namespace should raise ``ModuleNotFoundError`` rather than failing in some
    less predictable way.
    """
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("volttron.plugins.vctl")


def test_vctl_subparser_registry_is_empty_when_no_plugins_installed(no_auth_plugin_path):
    """
    Verify that the vctl subparser registry is empty without plugins.

    This test assumes no other plugin modules have already populated the
    registry during the same test session.
    """
    from volttron.client.decorators import vctl_subparser

    assert vctl_subparser.registry == {}


def test_control_flow_handles_missing_vctl_namespace_gracefully(no_auth_plugin_path):
    """
    Verify that missing plugin namespaces can be handled gracefully.

    This mirrors the control-path behavior where optional plugin imports are
    attempted and ``ModuleNotFoundError`` is intentionally caught so core vctl
    functionality can continue.
    """
    try:
        importlib.import_module("volttron.plugins.vctl")
    except ModuleNotFoundError:
        caught = True
    else:
        caught = False

    assert caught is True
