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
# TODO Add back in with plugin architecture
# from .rmq_pubsub import RMQPubSub
from volttron.client.vip.agent.subsystems.web import WebSubSystem

__all__ = [
    "PeerList",
    "Ping",
    "RPC",
    "Hello",
    "PubSub",
    #"RMQPubSub",
    "Channel",
    "Heartbeat",
    "Health",
    "ConfigStore",
    "Auth",
    "WebSubSystem"
]
