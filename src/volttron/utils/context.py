# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2022 Battelle Memorial Institute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ===----------------------------------------------------------------------===
# }}}

from configparser import ConfigParser

# used to make sure that volttron_home hasn't be modified
# since written to disk.
import logging
import os
from pathlib import Path
from typing import Optional

from .frozendict import FrozenDict

_log = logging.getLogger(__name__)


class ClientContext:
    """
    The `ClientContext` class is the single source of truth within
    a process running this system.
    """

    __volttron_home__: Optional[Path] = None
    __config__: dict = {}
    __config_keys__ = ("vip-address", "bind-web-address", "instance-name", "message-bus",
                       "web-ssl-cert", "web-ssl-key", "web-secret-key", "secure-agent-users")

    @classmethod
    def __load_config__(cls: "ClientContext"):
        if not cls.__config__:
            cls.__config__ = FrozenDict()

            volttron_home = ClientContext.get_volttron_home()
            config_file = os.path.join(volttron_home, "config")
            if os.path.exists(config_file):
                parser = ConfigParser()
                parser.read(config_file)
                options = parser.options("volttron")
                for option in options:
                    cls.__config__[option] = parser.get("volttron", option)
                cls.__config__.freeze()
        return cls.__config__

    @classmethod
    def get_config_param(cls, key: str, default: Optional[str] = None) -> Optional[str]:

        ClientContext.__load_config__()
        return cls.__config__.get(key, default)

    @classmethod
    def is_rabbitmq_available(cls):
        rabbitmq_available = True
        try:
            import pika

            rabbitmq_available = True
        except ImportError:
            os.environ["RABBITMQ_NOT_AVAILABLE"] = "True"
            rabbitmq_available = False
        return rabbitmq_available

    @classmethod
    def get_volttron_home(cls) -> str:
        """
        Return the VOLTTRON_HOME directory specified or default directory.

        If the VOLTTRON_HOME environment variable is set, it used.
        Otherwise, the default value of '~/.volttron' is used.

        If the volttron_home does not exist then this function will create
        it if possible.  This function also creates a check file for the
        VOLTTRON_HOME such that if the VOLTTRON_HOME is modified during
        runtime it will be detected and cause an error.

        @return:str:
            The absolute path to the volttron_home.
        """

        # vhome to test against for modification.
        vhome = (Path(os.environ.get("VOLTTRON_HOME", "~/.volttron")).expanduser().resolve())

        # cls variable is set the first time through this function
        # so we test to make sure nothing has changed from vhome and
        # the cls.__volttron_home__ variable.
        if cls.__volttron_home__:
            if vhome != cls.__volttron_home__:
                raise ValueError("VOLTTRON_HOME has been changed.  Possible nefarious act!")

        # Initialize class variable here and write a file inside the
        # volttron_home that we can check against.
        if cls.__volttron_home__ is None:
            cls.__volttron_home__ = vhome

            if not vhome.exists():
                # python 3.6 doesn't support pathlike object in mkdir
                os.makedirs(str(vhome), exist_ok=True)

        return str(vhome)

    @classmethod
    def get_fq_identity(cls, identity, platform_instance_name=None):
        """
        Return the fully qualified identity for the passed core identity.

        Fully qualified identities are instance_name.identity

        :param identity:
        :param platform_instance_name: str The name of the platform.
        :return:
        """
        if not platform_instance_name:
            platform_instance_name = cls.get_config_param("instance-name")
        return f"{platform_instance_name}.{identity}"

    @classmethod
    def get_messagebus(cls):
        """Get type of message bus - zeromq or rabbbitmq."""
        return cls.get_config_param("message-bus")

    @classmethod
    def get_instance_name(cls):
        """Get type of message bus - zeromq or rabbbitmq."""
        instance_name = cls.get_config_param('instance-name', None)
        if instance_name is not None:
            instance_name = instance_name.strip('"')

        if not instance_name:
            _log.warning("Using hostname as instance name.")
            if os.path.isfile('/etc/hostname'):
                with open('/etc/hostname') as f:
                    instance_name = f.read().strip()

        return instance_name

    @classmethod
    def is_web_enabled(cls):
        """Returns True if web enabled, False otherwise"""
        if cls.get_config_param("bind-web-address"):
            return True
        return False

    @classmethod
    def is_secure_mode(cls):
        """Returns True if running in secure mode, False otherwise"""
        secure_mode = cls.get_config_param("secure-agent-users", False)
        if secure_mode:
            secure_mode = secure_mode.upper() == "TRUE"
        return secure_mode

    @classmethod
    def get_server_key(cls):
        """Returns server key"""
        from volttron.utils.keystore import KeyStore
        keystore_path = os.path.join(cls.get_volttron_home(), "keystore")
        keystore = KeyStore(keystore_path)
        return keystore.public

    @classmethod
    def get_agent_keys(cls, vip_id):
        from volttron.utils.keystore import KeyStore
        keystore_path = os.path.join(cls.get_volttron_home(), "agents", vip_id, "keystore.json")
        keystore = KeyStore(keystore_path)
        return keystore.public, keystore.secret
