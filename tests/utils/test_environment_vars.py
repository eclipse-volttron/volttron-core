# -*- coding: utf-8 -*- {{{
# vim: set fenc=utf-8 ft=python sw=4 ts=4 sts=4 et:
#
# Copyright 2020, Battelle Memorial Institute.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This material was prepared as an account of work sponsored by an agency of
# the United States Government. Neither the United States Government nor the
# United States Department of Energy, nor Battelle, nor any of their
# employees, nor any jurisdiction or organization that has cooperated in the
# development of these materials, makes any warranty, express or
# implied, or assumes any legal liability or responsibility for the accuracy,
# completeness, or usefulness or any information, apparatus, product,
# software, or process disclosed, or represents that its use would not infringe
# privately owned rights. Reference herein to any specific commercial product,
# process, or service by trade name, trademark, manufacturer, or otherwise
# does not necessarily constitute or imply its endorsement, recommendation, or
# favoring by the United States Government or any agency thereof, or
# Battelle Memorial Institute. The views and opinions of authors expressed
# herein do not necessarily state or reflect those of the
# United States Government or any agency thereof.
#
# PACIFIC NORTHWEST NATIONAL LABORATORY operated by
# BATTELLE for the UNITED STATES DEPARTMENT OF ENERGY
# under Contract DE-AC05-76RL01830
# }}}
import os

import mock
import pytest

from src.volttron.utils import vip_main


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
