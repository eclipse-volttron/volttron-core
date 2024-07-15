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

import logging
from pathlib import Path
from typing import List

import yaml

from volttron.utils.commands import (is_volttron_running, execute_command, isapipe,
                                     wait_for_volttron_startup, wait_for_volttron_shutdown,
                                     vip_main)
from volttron.utils.context import ClientContext
from volttron.utils.commands import wait_for_volttron_startup, wait_for_volttron_shutdown
from volttron.utils.dynamic_helper import get_module, get_class, get_subclasses
from volttron.utils.file_access import create_file_if_missing
from volttron.utils.frame_serialization import serialize_frames, deserialize_frames
from volttron.utils.keystore import encode_key, decode_key
from volttron.utils.identities import normalize_identity, is_valid_identity
from volttron.utils.jsonapi import strip_comments, parse_json_config
from volttron.utils.logs import setup_logging, log_to_file
from volttron.utils.messagebus import store_message_bus_config
from volttron.utils.network import get_address, get_hostname, is_ip_private
from volttron.utils.time import (format_timestamp, process_timestamp, parse_timestamp_string,
                                 get_utc_seconds_from_epoch, get_aware_utc_now,
                                 fix_sqlite3_datetime)
from volttron.utils.version import get_version

_log = logging.getLogger(__name__)


def load_config(config_path):
    """Load a JSON-encoded configuration file."""
    if not config_path or not Path(config_path).exists():
        raise ValueError("Invalid config_path sent to function.")

    # First attempt parsing the file with a yaml parser (allows comments natively)
    # Then if that fails we fallback to our modified json parser.
    try:
        with open(config_path) as f:
            return yaml.safe_load(f.read())
    except yaml.YAMLError as e:
        try:
            with open(config_path) as f:
                return parse_json_config(f.read())
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
    "strip_comments", "setup_logging", "serialize_frames", "is_valid_identity", "isapipe",
    "is_volttron_running", "create_file_if_missing", "wait_for_volttron_shutdown",
    "process_timestamp", "parse_timestamp_string", "execute_command", "get_version",
    "get_aware_utc_now", "get_utc_seconds_from_epoch", "get_address", "deserialize_frames",
    "wait_for_volttron_startup", "normalize_identity", "ClientContext", "format_timestamp",
    "store_message_bus_config", "is_ip_private", "fix_sqlite3_datetime", "vip_main", "get_module",
    "get_class", "get_subclasses"
]
