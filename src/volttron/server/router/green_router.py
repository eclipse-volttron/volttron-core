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

from typing import Optional

import zmq
from zmq import green as _green

from volttron.types.peer import ServicePeerNotifier
from .router import Router


class GreenRouter(Router):
    """
    Greenlet friendly Router
    """

    def __init__(
        self,
        local_address,
        addresses=(),
        context=None,
        secretkey=None,
        publickey=None,
        default_user_id=None,
        monitor=False,
        tracker=None,
        volttron_central_address=None,
        instance_name=None,
        bind_web_address=None,
        volttron_central_serverkey=None,
        protected_topics={},
        external_address_file="",
        msgdebug=None,
        volttron_central_rmq_address=None,
        service_notifier=Optional[ServicePeerNotifier],
    ):
        self._context_class = _green.Context
        self._socket_class = _green.Socket
        self._poller_class = _green.Poller
        super(GreenRouter, self).__init__(
            local_address,
            addresses=addresses,
            context=context,
            secretkey=secretkey,
            publickey=publickey,
            default_user_id=default_user_id,
            monitor=monitor,
            tracker=tracker,
            volttron_central_address=volttron_central_address,
            instance_name=instance_name,
            bind_web_address=bind_web_address,
            volttron_central_serverkey=volttron_central_address,
            protected_topics=protected_topics,
            external_address_file=external_address_file,
            msgdebug=msgdebug,
            service_notifier=service_notifier,
        )

    def start(self):
        """Create the socket and call setup().

        The socket is save in the socket attribute. The setup() method
        is called at the end of the method to perform additional setup.
        """
        self.socket = sock = self._socket_class(self.context, zmq.ROUTER)
        sock.router_mandatory = True
        sock.tcp_keepalive = True
        sock.tcp_keepalive_idle = 180
        sock.tcp_keepalive_intvl = 20
        sock.tcp_keepalive_cnt = 6
        sock.set_hwm(6000)
        self.setup()
