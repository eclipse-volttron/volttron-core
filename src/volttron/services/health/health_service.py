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

import logging
from collections import defaultdict
from datetime import datetime

from volttron.client.known_identities import (CONTROL_CONNECTION, PLATFORM_HEALTH,
                                              PROCESS_IDENTITIES, CONTROL)
from volttron.client.vip.agent import RPC, Agent, Core
from volttron.server.decorators import service
# TODO: rmq addition
# from volttron.utils.rmq_config_params import RMQConfig
# from volttron.utils.rmq_setup import start_rabbit, RabbitMQStartError
# from volttron.services.auth.auth_service import AuthEntry, AuthFile
from volttron.types import Service
from volttron.types.service_interface import ServiceInterface
from volttron.utils import format_timestamp, set_agent_identity
from volttron.server.server_options import ServerOptions

_log = logging.getLogger(__name__)


@service
class HealthService(Agent):

    class Meta:
        identity = PLATFORM_HEALTH

    def __init__(self, options: ServerOptions, **kwargs):
        kwargs["identity"] = self.Meta.identity

        with set_agent_identity(self.Meta.identity):
            super().__init__(address=options.service_address, **kwargs)

        self._health_dict: dict = {}

    def peer_added(self, peer: str):
        """
        The `peer_added` method should be called whenever an agent is connected to the
        platform.

        :param peer: The identity of the agent connected to the platform
        """
        if peer not in self._health_dict:
            self._health_dict[peer] = dict()

        health = self._health_dict[peer]

        health["peer"] = peer
        health["service_agent"] = peer in PROCESS_IDENTITIES
        health["connected"] = format_timestamp(datetime.now())

    def peer_dropped(self, peer):
        # TODO: Should there be an option for  a db/log file for agents coming and going from the platform?
        self._health_dict[peer]["disconnected"] = format_timestamp(datetime.now())
        del self._health_dict[peer]

    @RPC.export
    def get_platform_health(self):
        """
        The `get_platform_health` retrieves all of the connected agent's health structures,
        except for the `CONTROL_CONNECTION` (vctl's known identity).  Vctl's identity is used for short
        term connections and is not relevant to the core health system.

        This function returns a dictionary in the form identity: values such as the following:

        .. code-block :: json

            {
                "listeneragent-3.3_35":
                {
                    "peer": "listeneragent-3.3_35",
                    "service_agent": False,
                    "connected": "2020-10-28T12:46:58.701119",
                    "last_heartbeat": "2020-10-28T12:47:03.709605",
                    "message": "GOOD"
                }
            }

        :return:
        """
        agents = {}
        # Ignore the connection from control in the health as it will only be around for a short while.
        if len(self._health_dict.items()) > 0:
            agents = {
                k: v
                for k, v in self._health_dict.items()
                if isinstance(v, dict) and v.get("peer") != CONTROL_CONNECTION
            }
        _log.debug(f"get_platform_health() -> {agents}")
        return agents

    def _heartbeat_updates(self, peer, sender, bus, topic, headers, message):
        """
        This method is called whenever a publish goes on the message bus from the
        heartbeat* topic.

        :param peer:
        :param sender:
        :param bus:
        :param topic:
        :param headers:
        :param message:
        :return:
        """
        # TODO: workaround for not getting notified by message bus when new peer connects
        #  should be ok for now as client side will cache and clear cache after sometime
        if sender not in self._health_dict:
            self._health_dict[sender] = dict()

        health = self._health_dict[sender]
        time_now = format_timestamp(datetime.now())
        if not health:
            health["connected"] = time_now
            health["peer"] = sender
            health["service_agent"] = sender in PROCESS_IDENTITIES

        health["last_heartbeat"] = time_now
        health["message"] = message

    @Core.receiver("onstart")
    def onstart(self, sender, **kwargs):
        self.vip.pubsub.subscribe("pubsub", "heartbeat", callback=self._heartbeat_updates)
        # pl = self.vip.rpc.call(CONTROL, "peerlist").get()
        # for peer in pl:
        #     self._health_dict[peer] =
