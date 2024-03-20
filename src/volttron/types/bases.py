from abc import ABC, abstractmethod, abstractproperty
from typing import TYPE_CHECKING

from gevent.subprocess import Popen

#if TYPE_CHECKING:
from volttron.client.vip.agent import Agent
from volttron.types.agent_context import AgentContext
from volttron.types.auth.auth_credentials import Credentials
from volttron.types.message import Message


class CoreLoop(ABC):

    @abstractmethod
    def loop(self, running_event):
        ...


class AgentBuilder(ABC):

    @abstractmethod
    def build_agent(**kwargs):
        ...


class AgentInstaller(ABC):

    @abstractmethod
    def install_agent(**kwargs):
        ...

    @abstractmethod
    def uninstall_agent(**kwargs):
        ...


class AgentExecutor(ABC):

    @abstractmethod
    def execute(identity: str) -> Popen:
        ...

    @abstractmethod
    def stop():
        ...


class AgentStarter(ABC):

    @abstractmethod
    def start(agent: Agent):
        ...

    @abstractmethod
    def stop():
        ...


class Connection(ABC):

    @abstractproperty
    def connected(self) -> bool:
        ...

    @abstractmethod
    def connect():
        ...

    @abstractmethod
    def disconnect():
        ...

    @abstractmethod
    def is_connected() -> bool:
        ...

    @abstractmethod
    def send_vip_message(message: Message):
        ...

    @abstractmethod
    def recieve_vip_message() -> Message:
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
    ...


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
