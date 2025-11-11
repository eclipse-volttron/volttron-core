from typing import Any, Optional
from abc import ABC, abstractmethod
from typing import Literal

from volttron.types.auth.auth_credentials import (Credentials, CredentialsCreator, CredentialsStore)

from volttron.types import Service, Identity

import volttron.types.auth.authz_types as authz


# TODO Make AuthorizationManager the Authorizer.
#  Below is not used
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
    def load(cls, authz_input: Any, **kwargs) -> authz.VolttronAuthzMap:
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
    def get_protected_rpcs(self, identity: authz.Identity) -> list[str]:
        ...

    @abstractmethod
    def check_rpc_authorization(self, *, identity: authz.Identity, method_name: authz.vipid_dot_rpc_method,
                                method_args: dict, **kwargs) -> bool:
        ...

    @abstractmethod
    def check_pubsub_authorization(self, *, identity: authz.Identity, topic_pattern: str, access: str,
                                   **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_role(self,
                             *,
                             name: str,
                             rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                             pubsub_capabilities: Optional[authz.PubsubCapabilities] = None,
                             **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_agent_group(self,
                                    *,
                                    name: str,
                                    identities: list[authz.Identity],
                                    roles: Optional[authz.AgentRoles] = None,
                                    rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                    pubsub_capabilities: Optional[authz.PubsubCapabilities] = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_agents_from_group(self, name: str, identities: list[authz.Identity]):
        ...

    @abstractmethod
    def add_agents_to_group(self, name: str, identities: list[authz.Identity]):
        ...

    @abstractmethod
    def create_or_merge_agent_authz(self,
                                    *,
                                    identity: str,
                                    protected_rpcs: list[str] = None,
                                    roles: Optional[authz.AgentRoles] = None,
                                    rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                    pubsub_capabilities: Optional[authz.PubsubCapabilities] = None,
                                    comments: str = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def get_agent_capabilities(self, *, identity: str) -> dict:
        ...

    @abstractmethod
    def create_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
        ...

    @abstractmethod
    def is_protected_topic(self, *, topic_name_pattern: str) -> bool:
        """Return True if the topic is protected, False otherwise.

        The topic_expression can be a str or regex pattern.  If the string or
        expression matches a protected topic then True is returned.  If not,
        False is returned.

        :param topic_name_pattern: The topic to check if it is protected.
        :type topic_name_pattern: str
        :return: True if the topic is protected, False otherwise.
        :rtype: bool
        """
        ...

    @abstractmethod
    def remove_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
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
    def create_agent(self, *, identity: str, **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_agent(self, *, identity: str, **kwargs) -> bool:
        ...

    @abstractmethod
    def has_credentials_for(self, *, identity: Identity) -> bool:
        ...

    @abstractmethod
    def create_credentials(self, *, identity: Identity):
        ...

    @abstractmethod
    def get_credentials(self, *, identity: Identity) -> Credentials:
        """
        Retrieve credentials for the given identity.

        :param identity: The identity to load from the credentials.
        :return: A credentials object
        :rtype: Credentials
        """
        ...

    @abstractmethod
    def remove_credentials(self, *, identity: Identity):
        ...

    @abstractmethod
    def is_credentials(self, *, identity: Identity) -> bool:
        ...

    # Authorization

    @abstractmethod
    def get_protected_rpcs(self, identity: authz.Identity) -> list[str]:
        """
        returns list of protected methods for a given identity
        """
        ...

    @abstractmethod
    def check_rpc_authorization(self, *, identity: authz.Identity, method_name: authz.vipid_dot_rpc_method,
                                method_args: dict, **kwargs) -> bool:
        """ should throw AuthException is calling agent(identity) is not authorized to access the
            method_name(vip_id.rpc_method) with the specific arguments method_args"""
        ...

    @abstractmethod
    def check_pubsub_authorization(self, *, identity: authz.Identity, topic_pattern: str,
                                   access: Literal["pubsub", "publish", "subscribe"], **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_role(self, *, name: str, rpc_capabilities: authz.RPCCapabilities,
                             pubsub_capabilities: authz.PubsubCapabilities, **kwargs) -> bool:
        ...

    @abstractmethod
    def create_or_merge_agent_group(self,
                                    *,
                                    name: str,
                                    identities: list[authz.Identity],
                                    roles: Optional[authz.AgentRoles] = None,
                                    rpc_capabilities: Optional[authz.RPCCapabilities] = None,
                                    pubsub_capabilities: Optional[authz.PubsubCapabilities] = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def remove_agents_from_group(self, name: str, identities: list[authz.Identity]):
        ...

    @abstractmethod
    def add_agents_to_group(self, name: str, identities: list[authz.Identity]):
        ...

    @abstractmethod
    def create_or_merge_agent_authz(self,
                                    *,
                                    identity: str,
                                    protected_rpcs: list[str] = None,
                                    roles: authz.AgentRoles = None,
                                    rpc_capabilities: authz.RPCCapabilities = None,
                                    pubsub_capabilities: authz.PubsubCapabilities = None,
                                    comments: str = None,
                                    **kwargs) -> bool:
        ...

    @abstractmethod
    def get_agent_capabilities(self, *, identity: str) -> dict:
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
    def create_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
        ...

    @abstractmethod
    def remove_protected_topics(self, *, topic_name_patterns: list[str]) -> bool:
        ...

    @abstractmethod
    def is_protected_topic(self, *, topic_name_pattern: str) -> bool:
        """Return True if the topic or pattern is protected, False otherwise.

        The topic_expression can be a str or regex pattern.  If the string or
        expression matches a protected topic then True is returned.  If not,
        False is returned.

        :param topic_name_pattern: The topic to check if it is protected.
        :type topic_name_pattern: str
        :return: True if the topic is protected, False otherwise.
        :rtype: bool
        """
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
