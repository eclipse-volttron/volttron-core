# isort: skip_file
from __future__ import annotations

from abc import ABC, abstractmethod, abstractproperty
from typing import TYPE_CHECKING

from gevent.subprocess import Popen

# Credentials must be imported before AgentContext!
from volttron.types.auth.auth_credentials import Credentials, CredentialsFactory
from volttron.types.agent_context import AgentContext
from volttron.types.message import Message
from pathlib import Path


class AbstractAgent(ABC):

    def get_credentials(self, identity: str) -> Credentials:
        """
        Retrieve credentials from the keystore.json file in the agent's directory

        If the file does not exist then raises an exception.  This method assumes
        that the current path is at the root of an installed agent.

        :param identity: The identity to load from the credentials.
        :return: A credentials object
        :rtype: Credentials
        """
        cred_path = Path("keystore.json")

        return CredentialsFactory.create_from_file(identity=identity, path=cred_path)


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

    @abstractproperty
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
    def recieve_vip_message(self) -> Message:
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
    def start(self, options: any):    #  ServerOptions):
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
