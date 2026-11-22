#!/usr/bin/env python3
"""
Tests for vctl behavior when no optional vctl plugins are installed.

Plugins are hidden for each test, however they are installed: an import hook makes every
``volttron.plugins.vctl`` import raise ``ModuleNotFoundError``, as it does in an environment without plugins,
and the plugin registry starts empty. (Removing ``sys.path`` entries, as these tests used to, only hid a plugin
installed on its own path entry; a plugin installed into ``site-packages`` stayed importable, so the tests failed
wherever volttron-lib-auth was installed.)
"""
import importlib
import importlib.abc
import sys

import pytest

PLUGIN_NAMESPACE = "volttron.plugins.vctl"


def _is_plugin_module(name: str) -> bool:
    return name == PLUGIN_NAMESPACE or name.startswith(PLUGIN_NAMESPACE + ".")


class _HidePlugins(importlib.abc.MetaPathFinder):
    """Import hook that makes the vctl plugin namespace look absent."""

    def find_spec(self, name, path=None, target=None):
        if _is_plugin_module(name):
            raise ModuleNotFoundError(f"No module named {name!r} (vctl plugins hidden by the test)", name=name)
        return None


@pytest.fixture
def no_vctl_plugins(monkeypatch):
    """Run the test as if no vctl plugins were installed, and restore the real state afterwards."""
    from volttron.client.decorators import vctl_subparser

    cached = {name: sys.modules.pop(name) for name in list(sys.modules) if _is_plugin_module(name)}
    monkeypatch.setattr(sys, "meta_path", [_HidePlugins(), *sys.meta_path])
    monkeypatch.setattr(vctl_subparser, "registry", {})
    yield
    sys.modules.update(cached)


def _vctl_commands(parser):
    return set(parser._subparsers._group_actions[0].choices)


def test_import_vctl_raises_when_no_plugins_installed(no_vctl_plugins):
    """Without plugins the optional namespace is missing: importing it raises ``ModuleNotFoundError``."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(PLUGIN_NAMESPACE)


def test_vctl_subparser_registry_is_empty_when_no_plugins_installed(no_vctl_plugins, tmp_path):
    """Building vctl's parser without plugins registers no plugin and adds no plugin command."""
    from volttron.client.commands.control import build_parser
    from volttron.client.decorators import vctl_subparser

    parser = build_parser(str(tmp_path))
    assert vctl_subparser.registry == {}
    assert not {"auth", "authz"} & _vctl_commands(parser)


def test_control_flow_handles_missing_vctl_namespace_gracefully(no_vctl_plugins, tmp_path):
    """vctl's plugin discovery catches the missing namespace, and the core commands still parse."""
    from volttron.client.commands.control import build_parser

    parser = build_parser(str(tmp_path))
    assert {"status", "install", "config", "start", "stop"} <= _vctl_commands(parser)
    assert parser.parse_args(["status"]).func.__name__ == "status_agents"
