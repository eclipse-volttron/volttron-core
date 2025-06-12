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
# isort: skip_file
from __future__ import annotations

import logging
import os

from volttron.types.auth.auth_credentials import Credentials
from volttron.types.agent_context import AgentContext, AgentOptions
from volttron.types import AbstractAgent

from .core import *
from .decorators import *
from .errors import *
from .subsystems import *

_log = logging.getLogger(__name__)


class Agent(AbstractAgent):

    class Subsystems(object):

        def __init__(self, *, owner: Agent, core: Core, options: AgentOptions):
            # heartbeat_autostart, heartbeat_period, enable_store, enable_web, enable_channel,
            #         message_bus, tag_vip_id, tag_refresh_interval):
            self.peerlist = PeerList(core=core)
            self.ping = Ping(core)
            self.rpc = RPC(core=core, owner=owner, peerlist_subsys=self.peerlist)
            self.hello = Hello(core=core)
            self.pubsub = PubSub(core=core,
                                 peerlist_subsys=self.peerlist,
                                 rpc_subsys=self.rpc,
                                 owner=self,
                                 tag_vip_id=options.tag_vip_id,
                                 tag_refresh_interval=options.tag_refresh_interval)
            self.health = Health(owner=owner, core=core, rpc=self.rpc)
            self.heartbeat = Heartbeat(owner,
                                       core,
                                       rpc=self.rpc,
                                       pubsub=self.pubsub,
                                       heartbeat_autostart=options.heartbeat_autostart,
                                       heartbeat_period=options.heartbeat_period)
            if options.enable_store:
                self.config = ConfigStore(owner, core, self.rpc)

            self.auth = Auth(owner, core, self.rpc)

    def __init__(self, *, credentials: Credentials = None, options: AgentOptions = None, address: str = None, **kwargs):

        from volttron.client.decorators import (get_connection_builder, get_core_builder)

        factory = get_core_builder(**kwargs)

        if options is None:
            options = AgentOptions()

        if credentials is None:
            if not (identity := os.environ.get('AGENT_VIP_IDENTITY')):
                raise ValueError(f"Environmental variable AGENT_VIP_IDENTITY not set!")

            credentials = self.get_credentials(identity)

        # TODO: We need to be able to get the address from environment probably here.
        context = AgentContext(credentials=credentials, options=options, address=address)

        # Build the core based upon what was loaded in the factory above.
        self.core = factory.build(owner=self, context=context)

        self.vip = Agent.Subsystems(owner=self, core=self.core, options=options)
        self.core.setup()
        self.vip.rpc.export(self.core.version, "agent.version")
        # except Exception as e:
        #     _log.exception("Exception creating Agent. {}".format(e))
        #     raise e


class BasicAgent(object):

    def __init__(self, **kwargs):
        kwargs.pop("identity", None)
        super(BasicAgent, self).__init__(**kwargs)
        self.core = BasicCore(self)


def build_agent(*, address=None, credentials: Credentials):
    raise NotImplementedError()


# def build_agent(address=None,
#                 identity=None,
#                 publickey=None,
#                 secretkey=None,
#                 timeout=10,
#                 serverkey=None,
#                 agent_class=Agent,
#                 volttron_central_address=None,
#                 volttron_central_instance_name=None,
#                 **kwargs) -> Agent:
#     """Builds a dynamic agent connected to the specifiedd address.

#     All key parameters should have been encoded with
#     :py:meth:`volttron.client.vip.socket.encode_key`

#     :param str address: VIP address to connect to
#     :param str identity: Agent's identity
#     :param str publickey: Agent's Base64-encoded CURVE public key
#     :param str secretkey: Agent's Base64-encoded CURVE secret key
#     :param str serverkey: Server's Base64-encoded CURVE public key
#     :param class agent_class: Class to use for creating the instance
#     :param int timeout: Seconds to wait for agent to start
#     :param kwargs: Any Agent specific parameters
#     :return: an agent based upon agent_class that has been started
#     :rtype: agent_class
#     """

#     address = address if address is not None else get_address()

#     # This is a fix allows the connect to message bus to be different than
#     # the one that is currently running.
#     if publickey is None or secretkey is None:
#         publickey, secretkey = get_server_keys()

#     message_bus = cc.get_messagebus()

#     try:
#         enable_store = kwargs.pop("enable_store")
#     except KeyError:
#         enable_store = False

#     agent = agent_class(address=address,
#                         identity=identity,
#                         publickey=publickey,
#                         secretkey=secretkey,
#                         serverkey=serverkey,
#                         volttron_central_address=volttron_central_address,
#                         volttron_central_instance_name=volttron_central_instance_name,
#                         message_bus=message_bus,
#                         enable_store=enable_store,
#                         **kwargs)
#     event = gevent.event.Event()
#     gevent.spawn(agent.core.run, event)
#     with gevent.Timeout(timeout):
#         event.wait()
#     return agent
