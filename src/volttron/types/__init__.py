# # -*- coding: utf-8 -*- {{{
# # ===----------------------------------------------------------------------===
# #
# #                 Installable Component of Eclipse VOLTTRON
# #
# # ===----------------------------------------------------------------------===
# #
# # Copyright 2022 Battelle Memorial Institute
# #
# # Licensed under the Apache License, Version 2.0 (the "License"); you may not
# # use this file except in compliance with the License. You may obtain a copy
# # of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# # WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# # License for the specific language governing permissions and limitations
# # under the License.
# #
# # ===----------------------------------------------------------------------===
# # }}}

# from typing import Any, Dict

# import gevent
# from gevent import Greenlet

# from volttron.types import Service
# from volttron.types.message import Message
# from volttron.types.server_config import ServerConfig

# __all__: list[str] = ['Service', 'Message', 'ServerConfig']
# isort: skip_file
from __future__ import annotations

from abc import ABC, abstractmethod
import os

from gevent.subprocess import Popen

from pathlib import Path

Identity = str
Tag = str


class AbstractAgent(ABC):

    def get_credentials(self, identity: Identity) -> Credentials:
        """
        Retrieve credentials from the keystore.json file in the agent's directory

        If the file does not exist then raises an exception.  This method assumes
        that the current path is at the root of an installed agent.

        :param identity: The identity to load from the credentials.
        :return: A credentials object
        :rtype: Credentials
        """
        # TODO: We need to not do it like this!
        cred_path = Path(os.environ.get(
            "VOLTTRON_HOME", "~/.volttron")).expanduser() / f"credentials_store/{identity}.json"
        return CredentialsFactory.load_credentials_from_file(cred_path)


class AbstractCore(ABC):

    @abstractmethod
    def setup(self):
        ...

    @abstractmethod
    def loop(self, running_event):
        ...

    @abstractmethod
    def send_vip(self, message: Message):
        ...


class CoreLoop(ABC):

    @abstractmethod
    def loop(self, running_event):
        ...


class AgentBuilder(ABC):

    @abstractmethod
    def build_agent(self, **kwargs):
        ...


class AgentInstaller(ABC):

    @abstractmethod
    def install_agent(self, **kwargs):
        ...

    @abstractmethod
    def uninstall_agent(self, **kwargs):
        ...


class AgentExecutor(ABC):

    @abstractmethod
    def execute(self, identity: str) -> Popen:
        ...

    @abstractmethod
    def stop(self):
        ...


class AgentStarter(ABC):

    @abstractmethod
    def start(self, agent: AbstractAgent):
        ...

    @abstractmethod
    def stop(self):
        ...


class Connection(ABC):

    @property
    @abstractmethod
    def connected(self) -> bool:
        ...

    @abstractmethod
    def connect(self):
        ...

    @abstractmethod
    def disconnect(self):
        ...

    @abstractmethod
    def is_connected(self) -> bool:
        ...

    @abstractmethod
    def send_vip_message(self, message: Message):
        ...

    @abstractmethod
    def receive_vip_message(self) -> Message:
        ...


class ConnectionBuilder(ABC):

    @abstractmethod
    def build(self, *, credentials: Credentials) -> Connection:
        ...


class CoreBuilder(ABC):

    @abstractmethod
    def build(self, *, context: AgentContext, owner: Agent = None) -> CoreLoop:
        ...


class Service(ABC):

    def retrieve_credentials(self) -> Credentials:
        if not hasattr(self, 'Meta'):
            raise ValueError(f'Meta class not defined in {self}')

        meta = getattr(self, 'Meta')

        if not hasattr(meta, 'identity'):
            raise ValueError(f'identity not found in Meta class for {self}')

        identity = getattr(meta, 'identity')

        from volttron.server.containers import service_repo
        from volttron.types.auth.auth_credentials import CredentialsStore
        creds = service_repo.resolve(CredentialsStore).retrieve_credentials(identity=identity)

        return creds


class MessageBus(ABC):

    @abstractmethod
    def start(self, options: any):    # ServerOptions):
        ...

    @abstractmethod
    def stop(self):
        ...

    @abstractmethod
    def is_running(self) -> bool:
        ...

    @abstractmethod
    def send_vip_message(self, message: Message):
        ...

    @abstractmethod
    def receive_vip_message(self) -> Message:
        ...


# Credentials must be imported before AgentContext!
from volttron.types.auth.auth_credentials import Credentials, CredentialsFactory
from volttron.types.agent_context import AgentContext
from volttron.types.message import Message

import volttron.types.known_host
