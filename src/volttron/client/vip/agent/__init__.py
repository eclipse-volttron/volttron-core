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

import logging as _log
import os

import gevent

from volttron.types.auth.auth_credentials import Credentials
from volttron.types.agent_context import AgentContext, AgentOptions
from volttron.types.bases import AbstractAgent
from volttron.utils import ClientContext as cc
from volttron.utils import is_valid_identity

from .core import *
from .decorators import *
from .errors import *
from .subsystems import *


class Agent(AbstractAgent):

    class Subsystems(object):

        def __init__(self, *, owner: Agent, core: Core, options: AgentOptions):
            #heartbeat_autostart, heartbeat_period, enable_store, enable_web, enable_channel,
            #         message_bus, tag_vip_id, tag_refresh_interval):
            self.peerlist = PeerList(core=core)
            self.ping = Ping(core)
            self.rpc = RPC(core=core, owner=owner, peerlist_subsys=self.peerlist)
            self.hello = Hello(core)
            # TODO Figure out how to hook up to pubsub.
            # if message_bus == "rmq":
            #     self.pubsub = RMQPubSub(core, self.rpc, self.peerlist, owner)
            # else:
            #     self.pubsub = PubSub(core, self.rpc, self.peerlist, owner, tag_vip_id, tag_refresh_interval)
            #     # Available only for ZMQ agents
            #     if enable_channel:
            #         self.channel = Channel(core)
            self.health = Health(owner, core, self.rpc)
            # self.heartbeat = Heartbeat(
            #     owner,
            #     core,
            #     self.rpc,
            #     self.pubsub,
            #     heartbeat_autostart,
            #     heartbeat_period,
            # )
            if options.enable_store:
                self.config = ConfigStore(owner, core, self.rpc)

            self.auth = Auth(owner, core, self.rpc)

    def __init__(self,
                 *,
                 credentials: Credentials = None,
                 options: AgentOptions = None,
                 address: str = None,
                 **kwargs):
        # TODO: Try to create them if possible
        # if credentials is None:
        #     if 'vip_identity' in kwargs:
        #         pass
        #     elif "identity" in kwargs:
        #         pass
        #     else:
        #         raise ValueError("Credentials or identity must be passed to the agent.")

        # if options is None:
        #     options = AgentOptions()
        #     for fld in options.__dataclass_fields__:
        #         if fld in kwargs:
        #             setattr(options, fld, kwargs.pop(fld))

        #raise ValueError("Either credentials or options must be provided.")

        #     identity=None,
        #     address=None,
        #     context=None,
        #     publickey=None,
        #     secretkey=None,
        #     serverkey=None,
        # # Since heartbeat is now 100% tied to status on the vctl change the defaults
        # # to auto start the heartbeat.
        #     heartbeat_autostart=True,
        #     heartbeat_period=60,
        #     volttron_home=None,
        #     agent_uuid=None,
        #     enable_store=True,
        #     enable_web=False,
        #     enable_channel=False,
        #     reconnect_interval=None,
        #     version="0.1",
        #     instance_name=None,
        #     message_bus=None,
        #     volttron_central_address=None,
        #     volttron_central_instance_name=None,
        #     tag_vip_id=None,
        #     tag_refresh_interval=-1
        # ):

        # if volttron_home is None:
        #     volttron_home = cc.get_volttron_home()
        from volttron.client.decorators import (get_connection_builder, get_core_builder)

        factory = get_core_builder(**kwargs)

        # if credentials.identity is None:
        #     raise ValueError("Agent identity is required.")

        # identity = credentials.identity
        # if identity is not None and not is_valid_identity(identity):
        #     _log.warning("Deprecation warning")
        #     _log.warning(
        #         "All characters in {identity} are not in the valid set.".format(identity=identity))

        if options is None:
            options = AgentOptions()

        if credentials is None:
            if not (identity := os.environ.get('AGENT_VIP_IDENTITY')):
                raise ValueError(f"Environmental variable AGENT_VIP_IDENTITY not set!")

            credentials = self.get_credentials(identity)

        # TODO: We need to be able to get the address from environment probably here.
        context = AgentContext(credentials=credentials, options=options, address=address)

        self.core = factory.build(owner=self, context=context)
        #self.core = get_core_instance(credentials=credentials)
        #self.core = core_cls(address=address, credentials=credentials, options=options)

        # if not tag_vip_id:
        #     # no value was sent, use what is configured in server config or default returned by cc
        #     tag_vip_id = cc.get_tag_vip_id()
        # if tag_refresh_interval == -1:
        #     # no value was sent, use what is configured in server config or default returned by cc
        #     tag_refresh_interval = cc.get_tag_refresh_interval()

        # self.vip = Agent.Subsystems(self, self.core, heartbeat_autostart, heartbeat_period, enable_store,
        #                             enable_web, enable_channel, message_bus, tag_vip_id, tag_refresh_interval)
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


def build_agent(address=None,
                identity=None,
                publickey=None,
                secretkey=None,
                timeout=10,
                serverkey=None,
                agent_class=Agent,
                volttron_central_address=None,
                volttron_central_instance_name=None,
                **kwargs) -> Agent:
    """Builds a dynamic agent connected to the specifiedd address.

    All key parameters should have been encoded with
    :py:meth:`volttron.client.vip.socket.encode_key`

    :param str address: VIP address to connect to
    :param str identity: Agent's identity
    :param str publickey: Agent's Base64-encoded CURVE public key
    :param str secretkey: Agent's Base64-encoded CURVE secret key
    :param str serverkey: Server's Base64-encoded CURVE public key
    :param class agent_class: Class to use for creating the instance
    :param int timeout: Seconds to wait for agent to start
    :param kwargs: Any Agent specific parameters
    :return: an agent based upon agent_class that has been started
    :rtype: agent_class
    """

    address = address if address is not None else get_address()

    # This is a fix allows the connect to message bus to be different than
    # the one that is currently running.
    if publickey is None or secretkey is None:
        publickey, secretkey = get_server_keys()

    message_bus = cc.get_messagebus()

    try:
        enable_store = kwargs.pop("enable_store")
    except KeyError:
        enable_store = False

    agent = agent_class(address=address,
                        identity=identity,
                        publickey=publickey,
                        secretkey=secretkey,
                        serverkey=serverkey,
                        volttron_central_address=volttron_central_address,
                        volttron_central_instance_name=volttron_central_instance_name,
                        message_bus=message_bus,
                        enable_store=enable_store,
                        **kwargs)
    event = gevent.event.Event()
    gevent.spawn(agent.core.run, event)
    with gevent.Timeout(timeout):
        event.wait()
    return agent
