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

import threading


class Monitor(threading.Thread):
    """Monitor thread to log connections."""

    def __init__(self, sock):
        super(Monitor, self).__init__()
        self.daemon = True
        self.sock = sock

    def run(self):
        events = {
            value: name[6:]
            for name, value in vars(zmq).items()
            if name.startswith("EVENT_") and name != "EVENT_ALL"
        }
        log = logging.getLogger("vip.monitor")
        if log.level == logging.NOTSET:
            log.setLevel(logging.INFO)
        sock = self.sock
        while True:
            event, endpoint = sock.recv_multipart()
            event_id, event_value = struct.unpack("=HI", event)
            event_name = events[event_id]
            log.info("%s %s %s", event_name, event_value, endpoint)
