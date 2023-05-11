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

from volttron.client import Agent


def test_subsystems_available():
    agent = Agent(enable_channel=True)
    assert agent.vip.auth
    assert agent.vip.channel
    assert agent.vip.config
    assert agent.vip.health
    assert agent.vip.heartbeat
    assert agent.vip.hello
    assert agent.vip.peerlist
    assert agent.vip.ping
    assert agent.vip.pubsub
    assert agent.vip.rpc

    # TODO: Add tests for enable/disable options.

    # agent = Agent(enable_store=False)

    # with pytest.raises(AttributeError):
    #     agent.vip.channel
    # with pytest.raises(NameError):
    #     getattr(agent.vip, "web")

    # with pytest.raises(AttributeError):
    #     assert not agent.vip.config

    # assert agent.vip.auth
    # assert agent.vip.health
    # assert agent.vip.heartbeat
    # assert agent.vip.hello
    # assert agent.vip.peerlist
    # assert agent.vip.ping
    # assert agent.vip.pubsub
    # assert agent.vip.rpc
