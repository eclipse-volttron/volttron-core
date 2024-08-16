from typing import Any, Optional
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from volttron.types.auth.auth_credentials import (Credentials, CredentialsCreator,
                                                  CredentialsStore)

from volttron.types import Service, Identity

import volttron.types.auth.authz_types as authz


class Authorizer(ABC):
    pass
    # @abstractmethod
    # def check_rpc_authorization(self, *, identity: authz.Identity, method_name: authz.vipid_dot_rpc_method,
    #                             method_args: dict, **kwargs) -> bool:
    #     ...
    #
    # @abstractmethod
    # def check_pubsub_authorization(self, *, identity: authz.Identity,
    #                                topic_pattern: str, access: str, **kwargs) -> bool:
    #     ...


class AuthzPersistence(ABC):

    @classmethod
    def load(cls, input: Any, **kwargs) -> authz.VolttronAuthzMap:
        ...

    @classmethod
    def store(cls, authz_map: authz.VolttronAuthzMap, **kwargs) -> bool:
        ...


class Authenticator(ABC):

    @abstractmethod
    def is_authenticated(self, *, identity: authz.Identity) -> bool:
        ...


class AuthorizationManager:

    @abstractmethod
    def check_rpc_authorization(self, *, identity: authz.Identity, method_name: authz.vipid_dot_rpc_method,
                                method_args: dict, **kwargs) -> bool:
        ...

    @abstractmethod
    def check_pubsub_authorization(self, *, identity: authz.Identity,
                                   topic_pattern: str, access: str, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_role(self, *, name: str, rpc_capabilities: authz.RPCCapabilities,
                             pubsub_capabilities: authz.PubsubCapabilities, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_agent_group(self,
                                    *,
                                    name: str,
                                    identities: set[authz.Identity],
                                    roles: authz.AgentRoles = None,
                                    rpc_capabilities: authz.RPCCapabilities = None,
                                    pubsub_capabilities: authz.PubsubCapabilities = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_agents_from_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def add_agents_to_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def create_or_merge_agent_authz(self,
                                    *,
                                    identity: str,
                                    protected_rpcs: set[authz.vipid_dot_rpc_method] = None,
                                    roles: authz.AgentRoles = None,
                                    rpc_capabilities: authz.RPCCapabilities = None,
                                    pubsub_capabilities: authz.PubsubCapabilities = None,
                                    comments: str = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def get_user_capabilities(self, *, identity: str) -> dict:
        ...

    @abstractmethod
    def create_protected_topic(self, *, topic_name_pattern: str) -> bool:
        ...

    @abstractmethod
    def remove_protected_topic(self, *, topic_name_pattern: str) -> bool:
        ...

    @abstractmethod
    def remove_agent_authorization(self, identity: authz.Identity):
        ...

    @abstractmethod
    def remove_agent_group(self, name: str):
        ...

    @abstractmethod
    def remove_role(self, name: str):
        ...


class AuthService(Service):

    # Authentication
    @abstractmethod
    def create_user(self, *, identity: str, **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_user(self, *, identity: str, **kwargs) -> bool:
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
    def check_rpc_authorization(self, *, identity: authz.Identity, method_name: authz.vipid_dot_rpc_method,
                                method_args: dict, **kwargs) -> bool:
        """ should throw AuthException is calling user(identity) is not authorized to access the
            method_name(vip_id.rpc_method) with the specific arguments method_args"""
        ...

    @abstractmethod
    def check_pubsub_authorization(self, *, identity: authz.Identity,
                                   topic_pattern: str, access: str, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_role(self, *, name: str, rpc_capabilities: authz.RPCCapabilities,
                             pubsub_capabilities: authz.PubsubCapabilities, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_agent_group(self,
                                    *,
                                    name: str,
                                    users: set[authz.Identity],
                                    roles: Optional[authz.AgentRoles] = None,
                                    rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                    pubsub_capabilities: Optional[authz.PubsubCapabilities] = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_agents_from_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def add_agents_to_group(self, name: str, identities: set[authz.Identity]):
        ...

    @abstractmethod
    def create_or_merge_agent_authz(self,
                                    *,
                                    identity: str,
                                    protected_rpcs: set[authz.vipid_dot_rpc_method] = None,
                                    roles: authz.AgentRoles = None,
                                    rpc_capabilities: authz.RPCCapabilities = None,
                                    pubsub_capabilities: authz.PubsubCapabilities = None,
                                    comments: str = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def get_user_capabilities(self, *, identity: str) -> dict:
        ...

    @abstractmethod
    def client_connected(self, *, credentials: Credentials):
        """
        The client_connected method is called when a client connects to the
        message bus.

        :param credentials: The credentials of the client that connected.
        :type credentials: Credentials
        """
        ...

    # def add_credential_to_role(credential: Credentials, role: str) -> None:
    #     ...

    @abstractmethod
    def create_protected_topic(self, *, topic_name_pattern: str) -> bool:
        ...

    @abstractmethod
    def remove_protected_topic(self, *, topic_name_patter: str) -> bool:
        ...

    @abstractmethod
    def remove_agent_authorization(self, name: authz.Identity):
        ...

    @abstractmethod
    def remove_agent_group(self, name: str):
        ...

    @abstractmethod
    def remove_role(self, name: str):
        ...
