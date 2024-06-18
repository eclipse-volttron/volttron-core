from typing import Any, Optional
from abc import ABC, abstractmethod

from volttron.types.auth.auth_credentials import (Credentials, CredentialsCreator,
                                                  CredentialsStore)
from volttron.types.bases import Service
import volttron.types.auth.authz_types as authz


class Authorizer(ABC):

    @abstractmethod
    def is_authorized(self, *, user: str, resource: Any, action: Any, **kwargs) -> bool:
        ...


class AuthzPersistence(ABC):

    @classmethod
    def load(cls, input: Any, **kwargs) -> authz.VolttronAuthzMap:
        ...

    @classmethod
    def store(cls, authz_map: authz.VolttronAuthzMap, **kwargs) -> bool:
        ...


class Authenticator(ABC):

    @abstractmethod
    def authenticate(self, *, credentials: Credentials) -> bool:
        ...


class AuthorizationManager(Service):

    @abstractmethod
    def create_or_merge_role(self,
                             *,
                             name: str,
                             rpc_capabilities: authz.RPCCapabilities,
                             pubsub_capabilities: authz.PubsubCapabilities,
                             **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_user_group(self, *, name: str,
                                   users: set[authz.Identity],
                                   roles: authz.UserRoles = None,
                                   rpc_capabilities: authz.RPCCapabilities = None,
                                   pubsub_capabilities: authz.PubsubCapabilities = None,
                                   **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_users_from_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def add_users_to_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def create_or_merge_user(self, *, identity: str, protected_rpcs: set[authz.vipid_dot_rpc_method] = None,
                             roles: authz.UserRoles = None, rpc_capabilities: authz.RPCCapabilities = None,
                             pubsub_capabilities: authz.PubsubCapabilities = None, comments: str = None,
                             domain: str = None, address: str = None, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_protected_topic(self, *, topic_name_pattern: str) -> bool:
        ...

    @abstractmethod
    def remove_protected_topic(self, *, topic_name_pattern: str) -> bool:
        ...

    @abstractmethod
    def remove_user(self, identity: authz.Identity):
        ...

    @abstractmethod
    def remove_user_group(self, name: str):
        ...

    @abstractmethod
    def remove_role(self, name: str):
        ...


class AuthService(Service):

    # Authentication

    @abstractmethod
    def authenticate(self, *, credentials: Credentials) -> bool:
        ...

    @abstractmethod
    def has_credentials_for(self, *, identity: str) -> bool:
        ...

    @abstractmethod
    def add_credentials(self, *, credentials: Credentials):
        ...

    @abstractmethod
    def remove_credentials(self, *, credentials: Credentials):
        ...

    @abstractmethod
    def is_credentials(self, *, identity: str) -> bool:
        ...

    # Authorization

    @abstractmethod
    def is_authorized(self, *, identity: authz.Identity, resource: Any, action: Any, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_role(self,
                             *,
                             name: str,
                             rpc_capabilities: authz.RPCCapabilities,
                             pubsub_capabilities: authz.PubsubCapabilities,
                             **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_user_group(self, *, name: str,
                                   users: set[authz.Identity],
                                   roles: Optional[authz.UserRoles] = None,
                                   rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                   pubsub_capabilities: Optional[authz.PubsubCapabilities] = None,
                                   **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_users_from_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def add_users_to_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def create_or_merge_user(self, *, identity: str, protected_rpcs: set[authz.vipid_dot_rpc_method] = None,
                             roles: authz.UserRoles = None, rpc_capabilities: authz.RPCCapabilities = None,
                             pubsub_capabilities: authz.PubsubCapabilities = None, comments: str = None,
                             domain: str = None, address: str = None, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_protected_topic(self, *, topic_name_pattern: str) -> bool:
        ...

    @abstractmethod
    def remove_protected_topic(self, *, topic_name_patter: str) -> bool:
        ...

    @abstractmethod
    def remove_user(self, name: authz.Identity):
        ...

    @abstractmethod
    def remove_user_group(self, name: str):
        ...

    @abstractmethod
    def remove_role(self, name: str):
        ...
