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

import gevent

from volttron.client.known_identities import CONTROL, CONTROL_CONNECTION
from volttron.client.vip.agent import Agent as BaseAgent
from volttron.types.agent_context import AgentContext, AgentOptions
from volttron.utils import ClientContext as cc

_log = logging.getLogger(__name__)


class ControlConnection(object):

    def __init__(self, address: str, peer=CONTROL):
        self.address = address
        _log.debug(f"Address is: {address} peer is: {peer}")
        self.peer = peer
        message_bus = cc.get_messagebus()

        from pathlib import Path

        from volttron.types.auth import Credentials, VolttronCredentials
        from volttron.utils import jsonapi
        credentials_path = Path(
            cc.get_volttron_home()) / "credentials_store" / f"{CONTROL_CONNECTION}.json"
        if not credentials_path.exists():
            raise ValueError(f"Control connection credentials not found at {credentials_path}")

        credjson = jsonapi.load(credentials_path.open("r"))

        credentials = VolttronCredentials(**credjson)
        options = AgentOptions(heartbeat_autostart=False,
                               volttron_home=cc.get_volttron_home(),
                               enable_store=False)
        self._server = BaseAgent(credentials=credentials, options=options, address=address)
        self._greenlet = None

    @property
    def server(self):
        if self._greenlet is None:
            # event = gevent.event.Event()
            # with gevent.Timeout(2):
            #     self._greenlet = gevent.spawn(self._server.core.run, event)
            #     event.wait()

            event = gevent.event.Event()
            self._greenlet = gevent.spawn(self._server.core.run, event)
            event.wait()
        return self._server

    def call(self, method, *args, **kwargs):
        _log.debug(f"Calling {self.peer} method: {method} with args {args}")
        assert self.server
        assert self.server.vip.rpc
        return self.server.vip.rpc.call(self.peer, method, *args, **kwargs).get(timeout=20)

    def call_no_get(self, method, *args, **kwargs):
        return self.server.vip.rpc.call(self.peer, method, *args, **kwargs)

    def notify(self, method, *args, **kwargs):
        return self.server.vip.rpc.notify(self.peer, method, *args, **kwargs)

    def kill(self, *args, **kwargs):
        if self._greenlet is not None:
            self._greenlet.kill(*args, **kwargs)
