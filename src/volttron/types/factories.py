from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from volttron.types.agent_context import AgentContext
from volttron.types.auth.auth_credentials import Credentials
from volttron.types import Connection, CoreLoop

if TYPE_CHECKING:
    from volttron.client.vip.agent import Agent


class ControlParser(ABC):

    @abstractmethod
    def get_parser(self) -> argparse.Parser:
        ...


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
