"""
decorators.py
=============

This module contains a factory registration function and several instances of it. It also
includes a function for logging traces.
"""
import inspect
import logging
import typing
from typing import TYPE_CHECKING, TypeVar

from volttron.client.vip.agent.core import Core
from volttron.server.containers import service_repo
from volttron.types.auth import (AuthService, Authenticator, AuthorizationManager, Authorizer,
                                 Credentials, CredentialsCreator, CredentialsStore)
from volttron.types import (AgentBuilder, AgentExecutor, AgentStarter, ConnectionBuilder,
                            CoreBuilder, MessageBus, Service)

T = TypeVar('T')


def factory_registration(registy_name: str,
                         interface: T = None,
                         singleton: bool = True,
                         allow_many: bool = False):
    """
    Create a factory registration function.

    The function will have a registry attribute that is a dictionary of registered
    classes and a name attribute that is the name of the factory.

    @param name: The name of the factory.
    @type name: str
    @return: The factory registration function.
    @rtype: function
    """

    def register(cls, **kwargs):
        lookup_key = None

        if hasattr(cls, 'Meta'):
            # Meta can either have a name or an identity, but not both.
            # We use either one of the values as a lookup for the register.
            if hasattr(cls.Meta, 'name') and hasattr(cls.Meta, 'identity'):
                raise ValueError("Only name or identity can be specified in Meta.")
            elif hasattr(cls.Meta, 'name'):
                lookup_key = cls.Meta.name
            elif hasattr(cls.Meta, 'identity'):
                lookup_key = cls.Meta.identity
        else:
            lookup_key = cls.__name__

        if lookup_key is None:
            raise ValueError(
                f"{cls.__name__} does not have an internal Meta class with identity or name.")

        # args = typing.get_args(interface)
        # if

        if interface is not None and not issubclass(cls, interface) and not isinstance(
                cls, interface):
            raise ValueError(f"{cls.__name__} doesn't implement {interface}")

        if singleton:
            if allow_many:
                service_repo.add_concrete_reference(interface, cls, kwargs=kwargs)
            else:
                service_repo.add_interface_reference(interface, cls, kwargs=kwargs)
        else:
            service_repo.add_factory(cls, cls, kwargs=kwargs)

        if lookup_key in register.registry:
            raise ValueError(f"{lookup_key} already in register for {register.name}.")
        register.registry[lookup_key] = cls
        return cls

    register.registy_name = registy_name
    register.registry = {}
    return register


# Allow many so lookup based upon concrete class rather than interface.
service = factory_registration("services", singleton=True, allow_many=True)

core_builder = factory_registration("core_builder", interface=CoreBuilder, singleton=True)
connection_builder = factory_registration("connection_bulider",
                                          interface=ConnectionBuilder,
                                          singleton=True)
authservice = factory_registration("authservice", interface=AuthService, singleton=True)

# credentials_store = factory_registration("credentials_store", interface=CredentialsStore)
# credentials_creator = factory_registration("credentials_creator", interface=CredentialsCreator)

# core = factory_registration("core", interface=Core, singleton=False)
# connection = factory_registration("connection", interface=Connection | ConnectionBuilder)
messagebus = factory_registration("messagebus", interface=MessageBus)

agent_starter = factory_registration("agent_starter", interface=AgentStarter)
agent_executor = factory_registration("agent_executor", interface=AgentExecutor)
agent_builder = factory_registration("agent_builder", interface=AgentBuilder)

# authorizer = factory_registration("authorizer", interface=Authorizer)
# authenticator = factory_registration("authenticator", interface=Authenticator)
# authorization_manager = factory_registration("authorization_manager",
#                                              interface=AuthorizationManager)

# auth_create_hook = factory_registration("auth_create_hook")
# auth_add_hook = factory_registration("auth_add_hook")
# auth_remove_hook = factory_registration("auth_remove_hook")
# auth_list_hook = factory_registration("auth_list_hook")


def __get_create_instance_from_factory__(*, instances, registration, name: str = None, **kwargs):
    if not registration.registry:
        raise ValueError(f"No {registration.registy_name} is currently registered")

    if name is None and len(registration.registry) > 1:
        raise ValueError(f"Can't figure out which messagebus to return.")

    the_instance = None
    if name is None:
        # First name of the registry dictionary.
        name = list(registration.registry.keys())[0]
        signature = inspect.signature(registration.registry[name].__init__)
        for k, v in kwargs.items():
            if k not in signature.parameters:
                raise ValueError(
                    f"Invalid parameter {k} for {name} signature has {signature.parameters}")

        instances[name] = registration.registry[name](**kwargs)
    elif name not in instances:
        instances[name] = registration.registry[name]()

    the_instance = instances.get(name)
    if the_instance is None:
        raise ValueError(f"Couldn't retrieve {name} from register")
    return the_instance


def __get_class_from_factory__(registration, name: str = None):
    if not registration.registry:
        raise ValueError(f"No {name} is currently registered")

    if name is None and len(registration.registry) > 1:
        raise ValueError(f"Can't figure out which messagebus to return.")

    if name is None:
        # First name of the registry dictionary.
        name = list(registration.registry.keys())[0]

    if name not in registration.registry:
        raise ValueError(f"Couldn't retrieve {name} from register")

    return registration.registry.get(name)


__messagebus__: dict[str, object] = {}


def get_messagebus_instance(name=None) -> MessageBus:
    return __get_create_instance_from_factory__(__messagebus__, messagebus, name)


__messagebus_core__: dict[str, object] = {}


def get_messagebus_core(name=None) -> object:
    return __get_create_instance_from_factory__(__messagebus_core__, core, name)


__messagebus_connection__: dict[str, object] = {}


def get_messagebus_core(name=None) -> object:
    """
    Return a messagebus connection instance.

    :param name: _description_, defaults to None
    :type name: _type_, optional
    :return: _description_
    :rtype: object
    """
    return __get_create_instance_from_factory__(__messagebus_connection__, connection, name)


def get_messagebus_class(name: str = None) -> type:
    """
    Return a registered messagebus class.

    :param name: The name of the registered messagebus class, defaults to None
    :type name: str, optional
    :return: The registered messagebus class
    :rtype: type
    :raises ValueError: If no messagebus class is registered or if the passed name doesn't
        exist in the registry
    """
    return __get_class_from_factory__(messagebus, name)


def get_core_instance(credentials: Credentials) -> Core:
    """
    Return a registered core class.

    :param name: The name of the registered core class, defaults to None
    :type name: str, optional
    :return: The registered core class
    :rtype: type
    :raises ValueError: If no core class is registered or if the passed name doesn't
        exist in the registry
    """
    registerd_cls = __get_class_from_factory__(core)
    service_repo.add_instance(Credentials, credentials)

    return service_repo.resolve(registerd_cls)
    # return __get_class_from_factory__(core, name)


__authorizer__: dict[str, Authorizer] = {}


def get_authorizer(name: str = None,
                   authorization_manager: AuthorizationManager = None) -> Authorizer:
    authorizer_instance: Authorizer = None
    if name is not None:
        authorizeritem = __authorizer__.get(name, None)

    # Use the default authorization manager if none is provided.
    if authorization_manager is None:
        authorization_manager = get_authorization_manager()

    assert isinstance(authorization_manager, AuthorizationManager)

    if authorizer_instance is None:
        authorizer_instance = __get_create_instance_from_factory__(
            instances=__authorizer__,
            registration=authorizer,
            name=name,
            authorization_manager=authorization_manager)
        if authorizer_instance is not None:
            __authorizer__[name] = authorizer_instance
    return authorizer_instance


__authenticator__: dict[str, Authenticator] = {}


def get_authenticator(name: str = None,
                      credentials_creator: CredentialsCreator = None) -> Authenticator:
    authenticatoritem: Authenticator = None
    if name is not None:
        authenticatoritem = __authenticator__.get(name, None)
    if credentials_creator is None:
        credentials_creator = get_credentials_creator()

    assert isinstance(credentials_creator, CredentialsCreator)

    if authenticatoritem is None:
        authenticatoritem = __get_create_instance_from_factory__(
            instances=__authenticator__,
            registration=authenticator,
            name=name,
            credentials_creator=credentials_creator)
        if authenticatoritem is not None:
            __authenticator__[name] = authenticatoritem
    return authenticatoritem


__credentials_store__: dict[str, CredentialsStore] = {}


def get_credentials_store(name: str = None) -> CredentialsStore:
    credentials_store_item: CredentialsStore = None
    if name is not None:
        credentials_store_item = __credentials_store__.get(name, None)
    if credentials_store_item is None:
        credentials_store_item = __get_create_instance_from_factory__(
            instances=__credentials_store__, registration=credentials_store, name=name)
        if credentials_store_item is not None:
            __credentials_store__[name] = credentials_store_item
    return credentials_store_item


__authorization_manager__: dict[str, AuthorizationManager] = {}


def get_authorization_manager(name: str = None) -> AuthorizationManager:
    auth_manager: AuthorizationManager = None
    if name is not None:
        auth_manager = __authorization_manager__.get(name, None)
    if auth_manager is None:
        auth_manager = __get_create_instance_from_factory__(instances=__authorization_manager__,
                                                            registration=authorization_manager,
                                                            name=name)
        if auth_manager is not None:
            __authorization_manager__[name] = auth_manager
    return auth_manager


def get_authservice_class(name=None) -> type:
    return __get_class_from_factory__(authservice, name)


__credentials_creator__: dict[str, CredentialsCreator] = {}


def get_credentials_creator(name=None) -> CredentialsCreator:
    creator_item: CredentialsCreator = None
    if name is not None:
        creator_item = __credentials_creator__.get(name, None)
    if creator_item is None:
        creator_item = __get_create_instance_from_factory__(instances=__credentials_creator__,
                                                            registration=credentials_creator,
                                                            name=name)
        if creator_item is not None:
            __credentials_creator__[name] = creator_item
    return creator_item


def get_services() -> dict[str, type]:
    return service.registry


def get_services_without_requires() -> list[type]:
    return list(filter(lambda x: not hasattr(x.Meta, "requires"), service.registry.values()))


def get_services_with_requires() -> list[type]:
    return list(filter(lambda x: hasattr(x.Meta, "requires"), service.registry.values()))


def get_service_class(identity: str) -> type:
    return service.registry[identity]


__service_instances__: dict[str, object] = {}


def get_service_instance(identity: str) -> object:
    return __get_create_instance_from_factory__(instances=__service_instances__,
                                                registration=service,
                                                name=identity)


def get_service_startup_order() -> list[str]:
    ordered: list[str] = ["platform.config"]

    for lookup, cls in service.registry.items():
        if lookup not in ('platform.config', ):
            ordered.append(lookup)

    return ordered


#    is_required_by: dict[str, list[str]] = {}

# for k, r in service.registry.items():
#     is_required_by[k] = r

# for k, r in service.registry.items():
#     if hasattr(r, "Meta") and hasattr(r.Meta, "requires"):
#         if isinstance(r.Meta.requires, str):
#             r.Meta.requires = [r.Meta.requires]

#         for require in r.Meta.requires:
#             is_required_by[require].append(k)
