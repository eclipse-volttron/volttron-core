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
AgentUUID = str
PathStr = Path | str


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
        cred_path = Path(os.environ.get("VOLTTRON_HOME",
                                        "~/.volttron")).expanduser() / f"credentials_store/{identity}.json"
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
    def setup(self):
        ...

    @property
    @abstractmethod
    def configuration(self):
        ...

    @property
    @abstractmethod
    def onsetup(self):
        ...

    @property
    @abstractmethod
    def onstart(self):
        ...

    @property
    @abstractmethod
    def ondisconnected(self):
        ...

    @property
    @abstractmethod
    def onconnected(self):
        ...

    @property
    @abstractmethod
    def identity(self) -> str:
        ...

    @property
    @abstractmethod
    def connection(self) -> Connection:
        ...

    @abstractmethod
    def loop(self, running_event):
        ...

    @property
    @abstractmethod
    def register(self, subsystem: str, handle_subsystem: Callable, handle_error: Callable):
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

    # @abstractmethod
    # def connect_remote_platform(self, platform_address: str, platform_id: str, 
    #                            public_credential: str) -> bool:
    #     """
    #     Connect to a remote platform with authentication
        
    #     :param platform_address: Address of the remote platform
    #     :param platform_id: ID of the remote platform
    #     :param public_credential: Public credential of the remote platform for authentication
    #     :return: True if connection succeeded
    #     """
    #     ...
        
    # @abstractmethod
    # def disconnect_remote_platform(self, platform_id: str) -> bool:
    #     """
    #     Disconnect from a remote platform
        
    #     :param platform_id: ID of the platform to disconnect from
    #     :return: True if disconnection succeeded
    #     """
    #     ...
        
    # @abstractmethod
    # def accept_remote_platform_connection(self, platform_id: str, public_credential: str) -> bool:
    #     """
    #     Configure the connection to accept connections from a specific remote platform
        
    #     :param platform_id: ID of the remote platform
    #     :param public_credential: Public credential of the remote platform for verification
    #     :return: True if successfully configured
    #     """
    #     ...


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

class MessageBusConfig(ABC):
    """Abstract base class for messagebus-specific configuration"""
    
    @classmethod
    @abstractmethod
    def get_defaults(cls) -> dict:
        """Get default configuration for this messagebus type"""
        pass
    
    @classmethod
    def create_from_options(cls, options_dict: dict[str, Any]) -> 'MessageBusConfig':
        """Create messagebus config from a dictionary of options
        
        This avoids direct dependency on ServerOptions
        """
        defaults = cls.get_defaults()
        # Merge defaults with provided options
        config = {**defaults, **options_dict}
        return cls(**config)

class MessageBus(ABC):
    # This should be set so it is called for the main
    # program clean up when either the `stop` method is
    # called.
    def __init__(self):
        self._stop_handler: Optional[MessageBusStopHandler] = None

    @abstractmethod
    def create_federation_bridge(self) -> Optional[FederationBridge]:
        """
        Create a federation bridge appropriate for this message bus
        
        :return: Federation bridge implementation or None if federation not supported
        """
        pass

    @abstractmethod
    def start(self):    # ServerOptions):
        ...

    @abstractmethod
    def stop(self):
        ...

    def set_stop_handler(self, value: MessageBusStopHandler):
        self._stop_handler = value

    def get_stop_handler(self) -> MessageBusStopHandler | None:
        return self._stop_handler

    @abstractmethod
    def is_running(self) -> bool:
        ...

    @abstractmethod
    def send_vip_message(self, message: Message):
        ...

    @abstractmethod
    def receive_vip_message(self) -> Message:
        ...


class MessageBusStopHandler(ABC):

    @abstractmethod
    def message_bus_shutdown(self):
        ...


# Credentials must be imported before AgentContext!
from volttron.types.auth.auth_credentials import Credentials, CredentialsFactory
from volttron.types.agent_context import AgentContext
from volttron.types.message import Message
from volttron.types.auth.auth_service import AuthService
from volttron.types.federation import FederationBridge

import volttron.types.known_host
