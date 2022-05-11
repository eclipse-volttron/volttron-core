# -*- coding: utf-8 -*- {{{
# vim: set fenc=utf-8 ft=python sw=4 ts=4 sts=4 et:
#
# Copyright 2020, Battelle Memorial Institute.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This material was prepared as an account of work sponsored by an agency of
# the United States Government. Neither the United States Government nor the
# United States Department of Energy, nor Battelle, nor any of their
# employees, nor any jurisdiction or organization that has cooperated in the
# development of these materials, makes any warranty, express or
# implied, or assumes any legal liability or responsibility for the accuracy,
# completeness, or usefulness or any information, apparatus, product,
# software, or process disclosed, or represents that its use would not infringe
# privately owned rights. Reference herein to any specific commercial product,
# process, or service by trade name, trademark, manufacturer, or otherwise
# does not necessarily constitute or imply its endorsement, recommendation, or
# favoring by the United States Government or any agency thereof, or
# Battelle Memorial Institute. The views and opinions of authors expressed
# herein do not necessarily state or reflect those of the
# United States Government or any agency thereof.
#
# PACIFIC NORTHWEST NATIONAL LABORATORY operated by
# BATTELLE for the UNITED STATES DEPARTMENT OF ENERGY
# under Contract DE-AC05-76RL01830
# }}}
"""The volttron.utils package contains generic utilities for handling json, storing configurations math libraries...and more."""

#from pbr.version import VersionInfo
import yaml

from .context import *
from .identities import *
from .time import *
from .file_access import *
from .frame_serialization import *
from .network import *
from .commands import *
from .jsonapi import strip_comments, parse_json_config
from .messagebus import store_message_bus_config
from .logging import *
from volttron.utils import math_utils as math

from .version import get_version

_log = logging.getLogger(__name__)
#__version__ = VersionInfo("volttron.utils")


def load_config(config_path):
    """Load a JSON-encoded configuration file."""
    if not config_path or not os.path.exists(config_path):
        raise ValueError("Invalid config_path sent to function.")

    # First attempt parsing the file with a yaml parser (allows comments natively)
    # Then if that fails we fallback to our modified json parser.
    try:
        with open(config_path) as f:
            return yaml.safe_load(f.read())
    except yaml.scanner.ScannerError as e:
        try:
            with open(config_path) as f:
                return parse_json_config(f.read())
        except Exception as e:
            _log.error("Problem parsing agent configuration")
            raise
