from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Type

from volttron.utils import get_class
from volttron.types.credentials import CredentialsManager, CredentialsGenerator
from volttron.types.message_bus import MessageBusInterface


def split_module_class(full_class):
    index = full_class.rindex(".")
    return full_class[:index], full_class[index+1:]


@dataclass
class ServerOptions:
    volttron_home: Path | str = field(default=Path("~/.volttron").expanduser())
    instance_name: str = None
    addresses: List[str] = None
    agent_isolation_mode_enabled: bool = False
    message_bus: str = "volttron.messagebus.zmq.ZmqMessageBus"
    credential_manager: str = "volttron.platform.auth.FileBasedCredentialManager"
    credential_generator: str = "volttron.messagebus.zmq.ZmqCredentialGenerator"
    auth_service: str = "volttron.services.auth"

    def __post_init__(self):
        if isinstance(self.volttron_home, str):
            self.volttron_home = Path(self.volttron_home)


class ServerRuntime:
    def __init__(self, opts: ServerOptions):
        self._opts = opts
        self._cred_manager_cls = get_class(*split_module_class(opts.credential_manager))
        self._message_bus_cls = get_class(*split_module_class(opts.message_bus))
        self._cred_generator_cls = get_class(*split_module_class(opts.credential_generator))
        self._auth_service_cls = opts.auth_service
        # There does not have to be an auth service.
        if opts.auth_service is not None:
            self._auth_service_cls = get_class(*split_module_class(opts.auth_service))

    @property
    def options(self):
        return self._opts

    @property
    def credential_generator_cls(self) -> Type[CredentialsGenerator]:
        return self._cred_generator_cls

    @property
    def credential_manager_cls(self) -> Type[CredentialsManager]:
        return self._cred_manager_cls

    @property
    def message_bus_cls(self) -> Type[MessageBusInterface]:
        return self._message_bus_cls

    @property
    def auth_service_cls(self):
        return self._auth_service_cls

