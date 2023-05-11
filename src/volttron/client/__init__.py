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

""" Core package."""
from typing import List

from gevent import monkey

# At this point these are the only things that need to be patched
# and the server and client are working harmoniously with this.
patches = [
    ('ssl', monkey.patch_ssl),
    ('socket', monkey.patch_socket),
    ('os', monkey.patch_os),
]

# patch modules if necessary.  Only if the module hasn't been patched before.
# this could happen if the server code uses the client (which it does).
for module, fn in patches:
    if not monkey.is_module_patched(module):
        fn()

import logging

from urllib.parse import urlparse

from volttron.client.vip.agent import Agent, build_agent
from volttron.client.vip.agent.core import Core
from volttron.client.vip.agent.subsystems.rpc import RPC
from volttron.client.vip.agent.subsystems.channel import Channel
from volttron.client.vip.agent.subsystems.hello import Hello
from volttron.client.vip.agent.subsystems.peerlist import PeerList
from volttron.client.vip.agent.subsystems.ping import Ping
from volttron.client.vip.agent.subsystems.pubsub import PubSub
from volttron.client.vip.agent.subsystems.rpc import RPC
from volttron.client.vip.agent.subsystems.heartbeat import Heartbeat
from volttron.client.vip.agent.subsystems.health import Health
from volttron.client.vip.agent.subsystems.configstore import ConfigStore
from volttron.client.vip.agent.subsystems.auth import Auth
from volttron.client.vip.agent.subsystems.query import Query

__all__: List[str] = [
    "Agent", "Core", "RPC", "Channel", "Hello", "PeerList", "Ping", "PubSub", "Heartbeat",
    "Health", "ConfigStore", "Auth", "Query"
]

_log = logging.getLogger(__name__)


def build_vip_address_string(vip_root, serverkey, publickey, secretkey):
    """Build a full vip address string based upon the passed arguments

    All arguments are required to be non-None in order for the string to be
    created successfully.

    :raises ValueError if one of the parameters is None.
    """
    _log.debug("root: {}, serverkey: {}, publickey: {}, secretkey: {}".format(
        vip_root, serverkey, publickey, secretkey))
    parsed = urlparse(vip_root)
    if parsed.scheme == "tcp":
        if not (serverkey and publickey and secretkey and vip_root):
            raise ValueError("All parameters must be entered.")

        root = "{}?serverkey={}&publickey={}&secretkey={}".format(vip_root, serverkey, publickey,
                                                                  secretkey)

    elif parsed.scheme == "ipc":
        root = vip_root
    else:
        raise ValueError("Invalid vip root specified!")

    return root


# def update_volttron_script_path(path: str) -> str:
#     """
#     Assumes that path's current working directory is in the root directory of the volttron codebase.

#     Prepend 'VOLTTRON_ROOT' to internal volttron script if 'VOLTTRON_ROOT' is set and return new path;
#     otherwise, return original path
#     :param path: relative path to the internal volttron script
#     :return: updated path to volttron script
#     """
#     if os.environ["VOLTTRON_ROOT"]:
#         args = path.split("/")
#         path = f"{os.path.join(os.environ['VOLTTRON_ROOT'], *args)}"
#     _log.debug(f"Path to script: {path}")
#     return path
