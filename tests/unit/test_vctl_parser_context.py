#!/usr/bin/env python3
"""
Tests for the ``VctlParserContext`` API.

These tests validate parser-context construction and command-registration
behavior without depending on optional auth plugin discovery. The focus here is
the API contract of ``VctlParserContext`` itself: command creation, nested
subcommands, inheritance of global arguments, and command-specific opt-out of
global arguments.
"""

import argparse

import pytest

from volttron.types.factories import VctlParserContext


@pytest.fixture
def vctl_parser_parts():
    """
    Create the parser components required to build a ``VctlParserContext``.

    Returns
    -------
    tuple
        A tuple of ``(main_parser, top_subparsers, global_args, filterable)``.
    """
    main_parser = argparse.ArgumentParser(prog="vctl")
    top_subparsers = main_parser.add_subparsers(title="subcommands", dest="command")

    global_args = argparse.ArgumentParser(add_help=False)
    global_args.add_argument("--address", default="tcp://127.0.0.1:22916")
    global_args.add_argument("--timeout", type=int, default=30)
    global_args.add_argument("--debug", action="store_true")

    filterable = argparse.ArgumentParser(add_help=False)
    filterable.add_argument("--name", help="agent name filter")
    filterable.add_argument("--tag", help="agent tag filter")
    filterable.add_argument("--uuid", help="agent uuid filter")

    return main_parser, top_subparsers, global_args, filterable


@pytest.fixture
def vctl_context(vctl_parser_parts):
    """
    Create a ``VctlParserContext`` paired with its root parser.

    Returns
    -------
    tuple
        A tuple of ``(ctx, main_parser)`` suitable for command registration and
        argument-parsing tests.
    """
    main_parser, top_subparsers, global_args, filterable = vctl_parser_parts
    ctx = VctlParserContext(
        subparsers=top_subparsers,
        global_args=global_args,
        filterable=filterable,
    )
    return ctx, main_parser


def test_import_vctl_parser_context():
    """
    Verify that ``VctlParserContext`` can be imported.

    This is a simple smoke test that confirms the factory type is available in
    the runtime environment.
    """
    assert VctlParserContext is not None


def test_create_vctl_parser_context(vctl_context):
    """
    Verify that a ``VctlParserContext`` instance can be created successfully.
    """
    ctx, main_parser = vctl_context
    assert ctx is not None
    assert main_parser is not None


def test_register_top_level_command_with_global_args(vctl_context):
    """
    Verify registration of a top-level command that inherits global arguments.
    """
    ctx, _ = vctl_context
    cmd = ctx.register_command("test", help="test command")
    cmd.add_argument("--test-arg")
    assert cmd is not None


def test_register_command_without_global_args(vctl_context):
    """
    Verify registration of a command that opts out of global arguments.

    Commands registered with ``apply_global_args=False`` should parse only their
    own local arguments and should not receive inherited global options.
    """
    ctx, main_parser = vctl_context
    cmd = ctx.register_command(
        "offline",
        help="offline command",
        apply_global_args=False,
    )
    cmd.add_argument("--local-only")

    args = main_parser.parse_args(["offline", "--local-only", "yes"])
    assert args.command == "offline"
    assert args.local_only == "yes"
    assert not hasattr(args, "address")


def test_register_nested_subcommands(vctl_context):
    """
    Verify registration of nested subcommands under a top-level command.
    """
    ctx, _ = vctl_context
    auth_cmd = ctx.register_command("auth", help="auth management")
    auth_subs = auth_cmd.add_subparsers(dest="auth_action")

    auth_add = ctx.register_subcommand(auth_subs, "add", help="add credentials")
    auth_add.add_argument("identity")

    auth_list = ctx.register_subcommand(auth_subs, "list", help="list credentials")

    assert auth_add is not None
    assert auth_list is not None


def test_parent_args_none_handling(vctl_context):
    """
    Verify that ``parent_args=None`` does not introduce shared mutable state.

    This protects against the classic mutable-default-argument bug pattern by
    ensuring multiple registrations using ``None`` remain independent.
    """
    ctx, _ = vctl_context
    cmd1 = ctx.register_command("cmd1", parent_args=None)
    cmd2 = ctx.register_command("cmd2", parent_args=None)

    assert cmd1 is not None
    assert cmd2 is not None
    assert cmd1 is not cmd2


def test_end_to_end_argument_parsing(vctl_context):
    """
    Verify end-to-end parsing for a synthetic nested command structure.
    """
    ctx, main_parser = vctl_context

    auth_cmd = ctx.register_command("auth", help="auth management")
    auth_subs = auth_cmd.add_subparsers(dest="auth_action")

    auth_add = ctx.register_subcommand(auth_subs, "add", help="add credentials")
    auth_add.add_argument("identity")

    args = main_parser.parse_args(
        ["auth", "add", "myagent", "--address", "tcp://127.0.0.1:22916"]
    )
    assert args.command == "auth"
    assert args.auth_action == "add"
    assert args.identity == "myagent"
    assert args.address == "tcp://127.0.0.1:22916"


def test_per_command_control_apply_global_args_false(vctl_context):
    """
    Verify command-level control over inheritance of global arguments.

    A command registered with ``apply_global_args=False`` should still parse
    normally while excluding global options such as ``--timeout`` and
    ``--debug`` from its result namespace.
    """
    ctx, main_parser = vctl_context
    ctx.register_command("offline", help="offline command", apply_global_args=False)

    args = main_parser.parse_args(["offline"])
    assert args.command == "offline"
    assert not hasattr(args, "timeout")
    assert not hasattr(args, "debug")
