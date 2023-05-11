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

import pytest
import gevent
from gevent.queue import Queue

# from gevent.queue import StopIteration
# from gevent.queue import Queue


@pytest.fixture(scope="module")
def messages():
    return Queue()


def fun1(messages):
    messages.put("fun1-1")
    gevent.sleep(0)
    messages.put("fun1-2")


def fun2(messages):
    messages.put("fun2-1")
    gevent.sleep(0)
    messages.put("fun2-2")


def test_yielding(messages):
    gevent.joinall([gevent.spawn(fun1, messages), gevent.spawn(fun2, messages)])
    messages.put(StopIteration)

    assert messages.get() == "fun1-1"
    assert messages.get() == "fun2-1"
    assert messages.get() == "fun1-2"
    assert messages.get() == "fun2-2"
