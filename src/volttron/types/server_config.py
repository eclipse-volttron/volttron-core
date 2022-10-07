from __future__ import annotations

from os import PathLike
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml

import volttron.server.aip as aipModule


def __all_ready_set__(property_name: str, value: Any):
    if value is not None:
        raise f"{property_name} has already been set and cannot be changed."


def __not_set__(property_name: str, value: Any):
    if not value:
        raise ValueError(f"{property_name} has not been set yet!")


class ServerConfig:

    def __init__(self):

        self.__aip__: aipModule = None
        self.__service_config_file__: Optional[PathLike] = None
        self.__auth_file__: Optional[PathLike] = None
        self.__protected_topics_file__: Optional[PathLike] = None
        self.__service_config_dict__: Dict = {}
        self.__internal_address__: Optional[str] = None
        self.__opts__ = None

    @property
    def opts(self):
        __not_set__("opts", self.__opts__)
        return self.__opts__

    @opts.setter
    def opts(self, value):
        __all_ready_set__("opts", self.__opts__)
        self.__opts__ = value

    @property
    def internal_address(self) -> str:
        __not_set__("internal_address", self.__internal_address__)
        return self.__internal_address__

    @internal_address.setter
    def internal_address(self, value):
        __all_ready_set__("internal_address", self.__internal_address__)
        self.__internal_address__ = value

    @property
    def service_config_file(self):
        __not_set__("service_config_file", self.__service_config_file__)
        return self.__service_config_file__

    @service_config_file.setter
    def service_config_file(self, value: PathLike):
        __all_ready_set__("service_config_file", self.__service_config_file__)
        if isinstance(value, str):
            value = Path(value)
        if not value.exists():
            raise ValueError(f"File {value} does not exists.")
        self.__service_config_file__ = value

    @property
    def aip(self) -> aipModule.AIPplatform:
        __not_set__("aip", self.__aip__)
        return self.__aip__

    @aip.setter
    def aip(self, value: aipModule.AIPplatform):
        if self.__aip__ is not None:
            raise ValueError("AIP has already been set and cannot be changed")
        self.__aip__ = value

    def get_service_enabled(self, service_name: str) -> bool:
        self.__init_service_dict__()
        service = self.__service_config_dict__.get(service_name)
        # Services don't have to be listed in the service_config.yml file so only if there is a
        # service listed do we consider whether they are enabled or not.
        retval = True
        if service is not None and "enabled" in service:
            retval = service["enabled"]
        return retval

    def get_service_kwargs(self, service_name: str) -> Dict:
        self.__init_service_dict__()
        service = self.__service_config_dict__.get(service_name, {})
        return {} if service is None else service.get("kwargs", {})

    def __init_service_dict__(self):
        if not self.__service_config_dict__:
            self.__service_config_dict__ = yaml.safe_load(self.__service_config_file__.open())

    @property
    def protected_topics_file(self) -> PathLike:
        return self.__protected_topics_file__

    @protected_topics_file.setter
    def protected_topics_file(self, value: PathLike):
        __all_ready_set__("protected_topics_file", self.__protected_topics_file__)
        if isinstance(value, str):
            value = Path(value)
        self.__protected_topics_file__ = value

    @property
    def auth_file(self) -> PathLike:
        __not_set__("auth_file", self.__auth_file__)
        return self.__auth_file__

    @auth_file.setter
    def auth_file(self, value: PathLike):
        __all_ready_set__("auth_file", self.__auth_file__)
        if isinstance(value, str):
            value = Path(value)
        self.__auth_file__ = value
