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

import os

import mock
import pytest

from volttron.utils import vip_main


class AgentMockery:
    myargs = None
    mykwargs = None

    def __init__(self, *args, **kwargs):
        AgentMockery.myargs = args
        AgentMockery.mykwargs = kwargs

    def run(self):
        pass


def test_env_args_passed_to_agent():
    env = dict(AGENT_PUBLICKEY="uSo_q3vw-DpcOeCOXc1A4o1U11qpTtkkW2EviHM7x24",
               AGENT_SECRETKEY="WpnCmf1vM1Z5gw0uIg8tr2C4erNQpSa0KONq9NvjzUE",
               VOLTTRON_SERVERKEY="UH4tX5RDNTMjp5VPxVuj-M5QiO82BLUghYeWJ_CgvQc")
    with mock.patch.dict(os.environ, env):
        vip_main(AgentMockery, identity="foo")
        assert env["AGENT_PUBLICKEY"] == AgentMockery.mykwargs['publickey']
        assert env["AGENT_SECRETKEY"] == AgentMockery.mykwargs['secretkey']
        assert env["VOLTTRON_SERVERKEY"] == AgentMockery.mykwargs['serverkey']


def test_env_only_publickey_passed_to_agent():
    env = dict(AGENT_PUBLICKEY="uSo_q3vw-DpcOeCOXc1A4o1U11qpTtkkW2EviHM7x24")
    with mock.patch.dict(os.environ, env):
        with pytest.raises(ValueError):
            vip_main(AgentMockery, identity="foo")
