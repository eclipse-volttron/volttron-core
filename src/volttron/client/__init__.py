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

from urllib.parse import urlparse

from volttron.client.vip.agent.core import Core
from volttron.client.vip.agent.subsystems.auth import Auth
from volttron.client.vip.agent.subsystems.configstore import ConfigStore
from volttron.client.vip.agent.subsystems.health import Health
from volttron.client.vip.agent.subsystems.heartbeat import Heartbeat
from volttron.client.vip.agent.subsystems.hello import Hello
from volttron.client.vip.agent.subsystems.peerlist import PeerList
from volttron.client.vip.agent.subsystems.ping import Ping
from volttron.client.vip.agent.subsystems.pubsub import PubSub
from volttron.client.vip.agent.subsystems.query import Query
from volttron.client.vip.agent.subsystems.rpc import RPC
from volttron.client.vip.agent import Agent
from volttron.types import AbstractAgent
from volttron.client.logs import setup_logging

__all__: List[str] = [
    "Agent", "AbstractAgent", "Core", "RPC", "Hello", "PeerList", "Ping", "PubSub", "Heartbeat", "Health",
    "ConfigStore", "Auth", "Query", "setup_logging"
]
