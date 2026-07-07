#!/usr/bin/env python3
"""
Integration tests for vctl plugin discovery and parser initialization.

This module exercises the end-to-end flow used by vctl when optional auth
plugins are installed. It validates namespace discovery, module import,
real plugin configuration, command registration, argument parsing, and registry
contents exposed through ``vctl_subparser``.
"""

import argparse
import importlib
import pkgutil

import pytest

from volttron.types.factories import VctlParserContext


authparser = pytest.importorskip("volttron.plugins.vctl.auth.authparser")
authzparser = pytest.importorskip("volttron.plugins.vctl.auth.authzparser")

AuthCtlParser = authparser.AuthCtlParser
AuthzCtlParser = authzparser.AuthzCtlParser


@pytest.fixture
def parser_context(monkeypatch):
    """
    Create a realistic parser context for integration tests.

    The fixture simulates the structure created by the main vctl entry point and
    also ensures ``VOLTTRON_HOME`` is defined for plugin code that expects it.

    Returns
    -------
    tuple
        A tuple of ``(ctx, main_parser)``.
    """
    monkeypatch.setenv("VOLTTRON_HOME", "/tmp/test_volttron_home")

    main_parser = argparse.ArgumentParser(prog="vctl", add_help=False)
    top_level_subparsers = main_parser.add_subparsers(
        title="subcommands",
        metavar="",
        dest="command",
    )

    global_args = argparse.ArgumentParser(add_help=False)
    global_args.add_argument(
        "--address",
        default="tcp://127.0.0.1:22916",
        help="Address of VOLTTRON platform",
    )
    global_args.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Communication timeout",
    )
    global_args.add_argument("--debug", action="store_true", help="Enable debug")

    filterable = argparse.ArgumentParser(add_help=False)
    filterable.add_argument("--name", help="Filter by agent name")
    filterable.add_argument("--tag", help="Filter by agent tag")
    filterable.add_argument("--uuid", help="Filter by agent UUID")

    ctx = VctlParserContext(
        subparsers=top_level_subparsers,
        global_args=global_args,
        filterable=filterable,
    )
    return ctx, main_parser


@pytest.fixture
def vctl_namespace():
    """
    Import the optional ``volttron.plugins.vctl`` namespace or skip the module.

    Returns
    -------
    module
        The imported vctl plugin namespace package.
    """
    return pytest.importorskip("volttron.plugins.vctl")


def test_vctl_namespace_is_importable(vctl_namespace):
    """
    Verify that the vctl namespace package can be imported when installed.
    """
    assert vctl_namespace is not None
    assert hasattr(vctl_namespace, "__path__")


def test_discover_plugin_modules(vctl_namespace):
    """
    Verify that plugin modules can be discovered via ``pkgutil.walk_packages``.
    """
    discovered = [
        (mod_name, is_pkg)
        for _, mod_name, is_pkg in pkgutil.walk_packages(
            vctl_namespace.__path__, vctl_namespace.__name__ + "."
        )
    ]
    assert isinstance(discovered, list)


def test_import_discovered_non_package_modules(vctl_namespace):
    """
    Verify that all discovered non-package plugin modules import cleanly.
    """
    failures = []

    for _, mod_name, is_pkg in pkgutil.walk_packages(
        vctl_namespace.__path__, vctl_namespace.__name__ + "."
    ):
        if is_pkg:
            continue
        try:
            importlib.import_module(mod_name)
        except Exception as exc:
            failures.append((mod_name, exc))

    assert failures == []


def test_import_and_configure_auth_plugin(parser_context):
    """
    Verify that the auth plugin can be instantiated and configured.
    """
    ctx, _ = parser_context
    plugin = AuthCtlParser()
    assert plugin is not None
    plugin.configure(ctx)


def test_import_and_configure_authz_plugin(parser_context):
    """
    Verify that the authz plugin can be instantiated and configured.
    """
    ctx, _ = parser_context
    plugin = AuthzCtlParser()
    assert plugin is not None
    plugin.configure(ctx)


def test_verify_parsers_are_registered(parser_context):
    """
    Verify that configuring auth plugins registers expected top-level commands.
    """
    ctx, main_parser = parser_context

    AuthCtlParser().configure(ctx)
    AuthzCtlParser().configure(ctx)

    subparsers_actions = [
        action
        for action in main_parser._subparsers._group_actions
        if isinstance(action, argparse._SubParsersAction)
    ]

    assert len(subparsers_actions) > 0

    choices = subparsers_actions[0].choices
    registered = sorted(choices.keys())

    assert "auth" in registered
    assert "authz" in registered


def test_parse_auth_command_with_arguments(parser_context):
    """
    Verify parsing of auth commands after plugin configuration.

    This covers both a nested command invocation and inheritance of configured
    global arguments.
    """
    ctx, main_parser = parser_context

    AuthCtlParser().configure(ctx)

    args = main_parser.parse_args(["auth", "add", "test_agent", "--domain", "mydomain"])
    assert args.command == "auth"

    args = main_parser.parse_args(
        ["auth", "list", "--address", "tcp://127.0.0.1:22916"]
    )
    assert args.command == "auth"
    assert args.address == "tcp://127.0.0.1:22916"


def test_verify_global_args_are_inherited(parser_context):
    """
    Verify that configured plugin commands inherit global parser arguments.
    """
    ctx, main_parser = parser_context

    AuthCtlParser().configure(ctx)

    args = main_parser.parse_args(["auth", "add", "agent1", "--timeout", "60", "--debug"])

    assert hasattr(args, "timeout")
    assert args.timeout == 60
    assert hasattr(args, "debug")
    assert args.debug is True


def test_per_command_control_apply_global_args(parser_context):
    """
    Verify that ``VctlParserContext`` can still register non-global commands.

    This integration check preserves coverage for the command-registration path
    in the same realistic parser structure used by plugin configuration tests.
    """
    ctx, main_parser = parser_context

    offline_cmd = ctx.register_command(
        "offline",
        help="offline command",
        apply_global_args=False,
    )
    assert offline_cmd is not None

    args = main_parser.parse_args(["offline"])
    assert args.command == "offline"


def test_registry_contains_registered_plugins():
    """
    Verify that the vctl subparser registry is exposed as a dictionary.
    """
    from volttron.client.decorators import vctl_subparser

    assert isinstance(vctl_subparser.registry, dict)


def test_registered_plugin_classes_expose_expected_metadata():
    """
    Verify that registered plugin classes expose expected metadata when present.
    """
    from volttron.client.decorators import vctl_subparser

    for name, cls in vctl_subparser.registry.items():
        assert cls is not None
        if hasattr(cls, "Meta") and hasattr(cls.Meta, "name"):
            assert cls.Meta.name


def test_registered_plugin_classes_can_be_instantiated():
    """
    Verify that registered plugin classes can be instantiated successfully.

    The instantiated plugin objects are also expected to expose a
    ``configure()`` method compatible with the vctl parser context.
    """
    from volttron.client.decorators import vctl_subparser

    for name, plugin_cls in vctl_subparser.registry.items():
        instance = plugin_cls()
        assert instance is not None
        assert hasattr(instance, "configure"), f"{name} is missing configure()"
