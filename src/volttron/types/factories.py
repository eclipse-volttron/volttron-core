from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from volttron.types.agent_context import AgentContext
from volttron.types.auth.auth_credentials import Credentials
from volttron.types import Connection, CoreLoop

if TYPE_CHECKING:
    from volttron.client.vip.agent import Agent


class VctlParserContext:
    """
    Context object passed to vctl plugin configure() methods.

    Provides a typed, self-documenting API for registering vctl commands and subcommands.
    Automatically handles:
    - Injection of global arguments (--address, --timeout, --debug)
    - Optional filter arguments (--name, --tag, --uuid)
    - Per-command control over argument inheritance via apply_global_args flag
    """

    def __init__(self, *, subparsers, global_args, filterable):
        """
        Initialize the context.

        :param subparsers: argparse subparsers action for top-level commands
        :param global_args: ArgumentParser with global options (--address, --timeout, etc.)
        :param filterable: ArgumentParser with filter options (--name, --tag, --uuid, etc.)
        """
        self._subparsers = subparsers
        self._global_args = global_args
        self.filterable = filterable

    def register_command(self, name, *, parent_args=None, apply_global_args=True, **kwargs):
        """
        Register a top-level vctl command (e.g., 'auth', 'cert', 'status').

        By default, the command inherits global arguments (--address, --timeout, etc.).
        Set apply_global_args=False for commands that work offline (e.g., cert operations).

        :param name: Command name (becomes a vctl subcommand)
        :param parent_args: Optional list of ArgumentParsers to inherit from
            (e.g., [self.filterable] for agent-filtering commands)
        :param apply_global_args: If True (default), include global args (--address, etc.).
            Set to False for offline commands or those that don't need platform connection.
        :param kwargs: Additional arguments passed to ArgumentParser.add_parser()
            (help, description, epilog, etc.)
        :return: ArgumentParser for this command (ready for .add_subparsers(), .add_argument(), etc.)
        """
        parents = list(parent_args or [])
        if apply_global_args:
            parents.append(self._global_args)
        return self._subparsers.add_parser(name, parents=parents, **kwargs)

    def register_subcommand(self, subparsers_action, name, *, parent_args=None,
                           apply_global_args=True, **kwargs):
        """
        Register a nested subcommand under a command's subparsers.

        Example:
            auth = ctx.register_command("auth", help="manage credentials")
            auth_subs = auth.add_subparsers(dest="auth_action")
            add_cmd = ctx.register_subcommand(auth_subs, "add", help="add credentials")

        By default, the subcommand inherits global arguments. Set apply_global_args=False
        for offline subcommands.

        :param subparsers_action: The subparsers action from parent_cmd.add_subparsers()
        :param name: Subcommand name
        :param parent_args: Optional list of ArgumentParsers to inherit from
        :param apply_global_args: If True (default), include global args.
            Set to False for offline subcommands.
        :param kwargs: Additional arguments for ArgumentParser.add_parser()
        :return: ArgumentParser for this subcommand
        """
        parents = list(parent_args or [])
        if apply_global_args:
            parents.append(self._global_args)
        return subparsers_action.add_parser(name, parents=parents, **kwargs)


class ControlParser(ABC):
    """
    Abstract base class for vctl command-line subparser plugins.

    Plugins should implement configure() to add their subcommand parser(s) to vctl.
    Plugins are discovered from volttron.plugins.vctl.* namespace packages.

    Example::

        @vctl_subparser
        class MyParser(ControlParser):
            class Meta:
                name = "mycommand"

            def configure(self, ctx: VctlParserContext):
                cmd = ctx.register_command("mycommand", help="my command")
                cmd.add_argument("--option", help="an option")
                cmd.set_defaults(func=my_handler)
    """

    @abstractmethod
    def configure(self, ctx: VctlParserContext) -> None:
        """
        Configure the plugin's subparser(s).

        Called at vctl startup to register commands. Use the context object's
        register_command() and register_subcommand() methods to add commands.

        :param ctx: VctlParserContext for registering commands
        """
        ...

    # Deprecated: kept for backward compatibility
    def get_parser(self):
        """Deprecated. Use configure() instead."""
        raise NotImplementedError("Use configure(ctx: VctlParserContext) instead")


class ConnectionBuilder(ABC):

    @abstractmethod
    def build(self, *, credentials: Credentials) -> Connection:
        ...


class CoreBuilder(ABC):

    @abstractmethod
    def build(self, *, context: AgentContext, owner: Agent = None) -> CoreLoop:
        ...

    # def __init__(self, core_cls: type[Core], connection_factory: ConnectionBuilder) -> None:
    #     self._core_cls = core_cls
    #     self._connection_factory = connection_factory

    # def create(self, credentials: Credentials, owner: Agent = None) -> Core:
    #     core = self._core_cls(credentials=credentials, connection_factory=self._connection_factory)
    #     return core

    # def register(cls: )
