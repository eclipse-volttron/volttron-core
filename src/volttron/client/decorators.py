import importlib
import inspect
import logging
import typing
from typing import TYPE_CHECKING, Optional, TypeVar

from volttron.client.vip.agent.core import Core
from volttron.types.auth.auth_credentials import Credentials
from volttron.types.factories import (ConnectionBuilder, ControlParser, CoreBuilder)

_log = logging.getLogger(__name__)

T = TypeVar('T')


def factory_registration(registry_name: str, protocol: T = None, singleton: bool = True, allow_many: bool = False):
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
            raise ValueError(f"{cls.__name__} does not have an internal Meta class with identity or name.")

        # args = typing.get_args(protocol)
        # if
        if protocol is not None and not protocol in cls.__bases__ and not isinstance(cls, protocol):
            raise ValueError(f"{cls.__name__} doesn't implement {protocol}")

        # if singleton:
        #     if allow_many:
        #         service_repo.add_concrete_reference(protocol, cls, kwargs=kwargs)
        #     else:
        #         service_repo.add_interface_reference(protocol, cls, kwargs=kwargs)
        # else:
        #     service_repo.add_factory(cls, cls, kwargs=kwargs)

        if lookup_key is None:
            _log.warning("Lookup key is none!")
        _log.debug(f"Registering {cls.__name__} as a {lookup_key}")
        if lookup_key in register.registry:
            _log.warning(f"{lookup_key} already in register for {register.registry_name}.")
            #raise ValueError(f"{lookup_key} already in register for {register.registry_name}.")
        register.registry[lookup_key] = cls
        return cls

    register.registry_name = registry_name
    register.registry = {}
    return register


core_builder = factory_registration("core_builder", protocol=CoreBuilder, singleton=True)
connection_builder = factory_registration("connection_bulider", protocol=ConnectionBuilder, singleton=True)
vctl_subparser = factory_registration("vctl_subparser", protocol=ControlParser)


def __get_class_from_factory__(*, registration, name: str = None):
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


__core_builder__: CoreBuilder = None
"""The builder unnamed lookups return, once chosen. Agent.__init__ looks up unnamed."""

__core_builders__: dict[str, CoreBuilder] = {}
"""One builder instance per registry name."""


def _builder_instance(name: str, kwargs: dict) -> CoreBuilder:
    builder = __core_builders__.get(name)
    if builder is None:
        cls = __get_class_from_factory__(registration=core_builder, name=name)
        specs = inspect.getfullargspec(cls.__init__)
        builder = cls() if len(specs.args) == 1 and specs.defaults is None else cls(**kwargs)
        __core_builders__[name] = builder
    return builder


def _default_builder_name() -> str:
    """The registry name an unnamed lookup uses.

    One registered builder is used. With several, the platform's message bus decides: a builder whose registry name,
    or whose ``messagebus`` attribute, equals the platform config's ``messagebus`` value. With none registered, the
    platform's message bus package is imported, which registers its builder.
    """
    from volttron.utils import ClientContext as cc
    bus = cc.get_messagebus() or "zmq"
    registry = core_builder.registry
    if not registry:
        importlib.import_module(f"volttron.messagebus.{bus}")
        registry = core_builder.registry
    if len(registry) == 1:
        return next(iter(registry))
    matches = [key for key, cls in registry.items() if key == bus or getattr(cls, "messagebus", None) == bus]
    if len(matches) == 1:
        return matches[0]
    raise ValueError(f"Can't choose a core builder for message bus {bus!r}: registered {sorted(registry)}, "
                     f"matching {sorted(matches)}. Pass name= to get_core_builder().")


def get_core_builder(name: Optional[str] = None, **kwargs) -> CoreBuilder:
    """The core builder registered as ``name``, or for unnamed lookups the platform's (see _default_builder_name).

    Each registered builder is created once and cached by name; ``kwargs`` are used only when it is created. An
    explicit name always returns that builder (it used to return whichever builder was cached first,
    volttron-core#361).
    """
    global __core_builder__
    if name is not None:
        return _builder_instance(name, kwargs)
    if __core_builder__ is None:
        __core_builder__ = _builder_instance(_default_builder_name(), kwargs)
    return __core_builder__


def get_connection_builder(name: Optional[str] = None) -> ConnectionBuilder:
    return __get_class_from_factory__(registration=connection_builder, name=name)


def reset_core_builder():
    """Forget every cached CoreBuilder, so the next get_core_builder() call creates fresh instances with empty
    per-instance state (e.g. agent_contexts, connection_builders on ZmqCoreBuilder). Call this whenever a new
    isolated server context is needed (e.g. between PlatformWrapper instances in tests)."""
    global __core_builder__
    __core_builder__ = None
    __core_builders__.clear()


def get_server_credentials(address: Optional[str] = None) -> Credentials:
    import os
    from pathlib import Path

    from volttron.types.auth import (Credentials, PKICredentials, PublicCredentials, VolttronCredentials)
    from volttron.types.known_host import KnownHostProperties as known_host_properties
    from volttron.client.known_identities import PLATFORM
    from volttron.utils import jsonapi

    # ipc address must mean we are local so use @ symbol to mean so.
    if address is None or address.startswith('ipc'):
        address = "@"

    cred_path = Path(os.environ['VOLTTRON_HOME']).expanduser() / f"credentials_store/{PLATFORM}.json"
    return VolttronCredentials.load_from_file(cred_path)

    new_path = Path(os.environ['VOLTTRON_HOME']) / "known_hosts.json"
    if known_host_properties is None:
        from volttron.types.known_host import _KnownHostProperties
        known_host_properties = _KnownHostProperties.load(new_path)

        # Handle original known_hosts file if necessary.
        old_path = Path(os.environ['VOLTTRON_HOME']) / "known_hosts"
        if old_path.exists():
            old_data = jsonapi.loads(old_path.open().read())
            if "@" in old_data:
                known_host_properties.add_property("@", "publickey", old_data["@"])

        known_host_properties.store(new_path)

    data = jsonapi.loads((Path(os.environ["VOLTTRON_HOME"]) / "keystore").open().read())

    # TODO This should only be necessary if there is in fact a credential store.
    # TODO Redo this thing here!
    known_host_properties.add_property(address, "publickey", data["public"])
    known_host_properties.store(new_path)
    publickey = known_host_properties.get_property(address, "publickey")

    # TODO This should only return the PublicCredentials instead of PKICredentials, but for now
    # TODO Verify the credentails for the server.
    return PKICredentials(identity="platform", publickey=data['public'], secretkey=data['secret'])

    # credential_type = os.environ.get("VOLTTRON_CREDENTIALS_TYPE")
    # credentials = os.environ.get("VOLTTRON_SERVER_CREDENTIALS")

    # if credentials is None:
    #     return Credentials.create(identity="server")

    # if credentials is not None and credential_type is None:
    #     raise ValueError("env VOLTTRON_CREDENTIALS is set but VOLTTRON_CREDENTIAL_TYPE is not set.")

    # if credentials is not None and credential_type is not None:
    #     if credential_type == "public":
    #         return PublicCredentials.from_json(Path(credentials).open().read())
    #     elif credential_type == "pki":
    #         return PKICredentials.from_json(Path(credentials).open().read())
    #     else:
    #         raise ValueError(f"Invalid VOLTTRON_CREDENTIAL_TYPE: {credential_type}")
