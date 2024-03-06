import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from volttron.types.auth.auth_credentials import (Credentials, CredentialsCreator,
                                                  CredentialsStore)

#from volttron.server.server_options import ServerOptions


class Authorizer(ABC):

    # def __init__(*, credentials_rules_map: any, **kwargs):
    #     ...
    @abstractmethod
    def is_authorized(self, *, role: str, action: str, resource: any, **kwargs) -> bool:
        ...


class Authenticator(ABC):

    @abstractmethod
    def authenticate(self, *, credentials: Credentials) -> bool:
        ...


class AuthorizationManager(ABC):

    @abstractmethod
    def create(self, *, role: str, action: str, filter: str | re.Pattern[str], resource: any,
               **kwargs) -> any:
        ...

    @abstractmethod
    def delete(self, *, role: str, action: str, filter: str | re.Pattern[str], resource: any,
               **kwargs) -> any:
        ...

    @abstractmethod
    def getall(self) -> list:
        ...

    @abstractmethod
    def has_role(self, role: str) -> bool:
        return role in self._role_map.mapping


class AuthService(ABC):

    @abstractmethod
    def is_authorized(credentials: Credentials, action: str, resource: str, **kwargs) -> bool:
        ...

    @abstractmethod
    def add_credentials(credentials: Credentials):
        ...

    @abstractmethod
    def remove_credentials(credentials: Credentials):
        ...

    @abstractmethod
    def is_credentials(identity: str) -> bool:
        ...

    @abstractmethod
    def has_credentials_for(identity: str) -> bool:
        ...

    @abstractmethod
    def add_role(role: str) -> None:
        ...

    @abstractmethod
    def remove_role(role: str) -> None:
        ...

    @abstractmethod
    def is_role(role: str) -> bool:
        ...

    # def add_credential_to_role(credential: Credentials, role: str) -> None:
    #     ...

    # def remove_credential_from_role(credential: Credentials, role: str) -> None:
    #     ...

    # def add_capability(name: str, value: str | list | dict, role: str = None, credential: Credentials = None) -> None:
    #     ...

    # def is_capability(name: str):
    #     ...

    # def remove_capability(name: str, role: str, credential: Credentials = None) -> None:
    #     ...
