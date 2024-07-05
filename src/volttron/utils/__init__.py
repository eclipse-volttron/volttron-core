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
"""The volttron.utils package contains generic utilities for handling json, storing configurations math
libraries...and more. """

from copy import deepcopy
import logging
import os
from pathlib import Path
from typing import List, TYPE_CHECKING
from contextlib import contextmanager

import yaml

from volttron.utils.commands import (is_volttron_running, execute_command, isapipe,
                                     wait_for_volttron_startup, wait_for_volttron_shutdown,
                                     vip_main)
from volttron.utils.context import ClientContext
from volttron.utils.commands import wait_for_volttron_startup, wait_for_volttron_shutdown
from volttron.utils.dynamic_helper import get_module, get_class, get_subclasses
from volttron.utils.file_access import create_file_if_missing
# from volttron.messagebus.zmq.serialize_frames import serialize_frames, deserialize_frames
# from volttron.utils.keystore import encode_key, decode_key
from volttron.utils.identities import normalize_identity, is_valid_identity
from volttron.utils.jsonapi import strip_comments, parse_json_config
from volttron.utils.logs import setup_logging, log_to_file
from volttron.utils.messagebus import store_message_bus_config
from volttron.utils.network import get_address, get_hostname, is_ip_private
from volttron.utils.time import (format_timestamp, process_timestamp, parse_timestamp_string,
                                 get_utc_seconds_from_epoch, get_aware_utc_now,
                                 fix_sqlite3_datetime)
from volttron.utils.version import get_version
from volttron.types import Identity

_log = logging.getLogger(__name__)


@contextmanager
def set_agent_identity(identity: Identity):
    """
    A context manager allowing setting and unsetting of the AGENT_VIP_IDENTITY.

    :param identity: the identity to set
    :type identity: Identity
    """
    env_key = "AGENT_VIP_IDENTITY"
    before = os.environ.get(env_key)
    os.environ[env_key] = identity
    yield
    if before is not None:
        os.environ[env_key] = identity


def load_config(default_configuration: str | Path | dict | None) -> dict:
    """
    Load the default configuration from a JSON or YAML encoded file.

    If default_configuration is None then return {}.

    If default_configuration is a dictionary, then return a deep copy of the dictionary
    without any changes to it.

    If default_configuration is a string or Path object, they must resolve to a file that
    is readable by the current process.  The file referenced will be parsed and loaded
    using yaml.safe_load.  Doing so will load both json or yaml based files.

    :param default_configuration: An agent configuration that is passed to __init__
    :type default_configuration: str | Path | dict
    :raises ValueError: If default_configuration is not resolvable.
    :return: A dictionary of the parsed default_configuration.
    :rtype: dict
    """

    if default_configuration is None:
        return {}

    if isinstance(default_configuration, dict):
        return deepcopy(default_configuration)

    if isinstance(default_configuration, str):
        default_configuration = Path(default_configuration).expanduser().absolute()
    elif isinstance(default_configuration, Path):
        default_configuration = default_configuration.expanduser().absolute()
    else:
        ValueError(
            f"Invalid type passed as default_configuration {type(default_configuration)} MUST be str | Path | dict | None"
        )

    # First attempt parsing the file with a yaml parser (allows comments natively)
    # Then if that fails we fallback to our modified json parser.
    try:
        return yaml.safe_load(default_configuration.read_text())
    except yaml.YAMLError as e:
        try:
            return parse_json_config(default_configuration.read_text())
        except Exception as e:
            _log.error("Problem parsing agent configuration")
            raise


def update_kwargs_with_config(kwargs, config):
    """
    Loads the user defined configurations into kwargs and converts any dash/hyphen in config variables into underscores
    :param kwargs: kwargs to be updated
    :param config: dictionary of user/agent configuration
    """

    for k, v in config.items():
        kwargs[k.replace("-", "_")] = v


__all__: List[str] = [
    "update_kwargs_with_config", "load_config", "parse_json_config", "get_hostname", "log_to_file",
    "strip_comments", "setup_logging", "is_valid_identity", "isapipe", "is_volttron_running",
    "create_file_if_missing", "wait_for_volttron_shutdown", "process_timestamp",
    "parse_timestamp_string", "execute_command", "get_version", "get_aware_utc_now",
    "get_utc_seconds_from_epoch", "get_address", "wait_for_volttron_startup", "normalize_identity",
    "ClientContext", "format_timestamp", "store_message_bus_config", "is_ip_private",
    "fix_sqlite3_datetime", "vip_main", "get_module", "get_class", "get_subclasses"
]
