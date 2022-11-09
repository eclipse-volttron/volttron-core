from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional

import gevent
from gevent import Greenlet

from volttron.types.credentials import Credentials, CredentialsManager
from volttron.types.errors import NotFoundError
from volttron.types.parameter import Parameter


@dataclass
class ConnectionParameters:
    """
    The ConnectionParameters is a base class for required parameters to
    connect to the MessageBus.  MessageBus implementors should inherit
    this class and add parameters that are required for the implementation.
    """
    address: str


@dataclass
class MessageBusParameters:
    credential_manager: Optional[CredentialsManager] = None
    auth_service: Optional["AuthService"] = None
    parameters: Set[Parameter] = field(default_factory=set)

    def add_parameter(self, parameter):
        self.parameters.add(parameter)

    def get_parameter(self, key: str) -> Parameter:
        for param in self.parameters:
            if param.key == key:
                return param
        raise NotFoundError(key, self)


class MessageBusInterface:
    """
    The MessageBusInterface is the main server available for connecting to.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.params = None
        self.auth_service = None

    def set_parameters(self, params: MessageBusParameters):
        self.params = params

    def initialize(self, **kwargs):
        raise NotImplementedError()

    def start(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def get_service_credentials(self) -> Credentials:
        """

        :return:
        """
        raise NotImplementedError()

    def get_server_credentials(self) -> Credentials:
        """
        This method is used in the initial setup of the platform and the server side services.
        The credentials of the server should be separate from the agents connecting to the platform.

        :return:
            A Credentials volttron.types.credentials.Credentials
        """
        raise NotImplementedError()

    @staticmethod
    def get_default_parameters() -> MessageBusParameters:
        raise NotImplementedError()


