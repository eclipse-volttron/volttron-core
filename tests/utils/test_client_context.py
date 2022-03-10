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
from pathlib import Path

import gevent
from unittest import mock
import pytest

from volttron.utils import ClientContext


@pytest.fixture
def undocontext():
    # Resets the context of volttron_home klass
    # variable (NOTE not sure if this is the best
    # way or not to undo this.)
    yield

    ClientContext.__volttron_home__ = None


def test_default_VOLTTRON_HOME(undocontext):
    # must be ~/.volttron as default
    path = Path("~/.volttron").expanduser().resolve()

    assert str(path) == ClientContext.get_volttron_home()
    assert Path(path).exists()


def test_can_use_VOLTTRON_HOME_DIR(create_volttron_home_fun_scope, monkeypatch, undocontext):

    original_volttron_home = create_volttron_home_fun_scope
    monkeypatch.setenv("VOLTTRON_HOME", original_volttron_home)

    volttron_home = ClientContext.get_volttron_home()

    assert original_volttron_home == volttron_home
    assert Path(volttron_home).exists()


def test_change_VOLTTRON_HOME_raises_exception(create_volttron_home_fun_scope, monkeypatch,
                                               undocontext):

    volttron_home = ClientContext.get_volttron_home()

    monkeypatch.setenv("VOLTTRON_HOME", "~/differnt_vhome")

    with pytest.raises(ValueError):
        other_vhome = ClientContext.get_volttron_home()

    monkeypatch.setenv("VOLTTRON_HOME", volttron_home)

    assert volttron_home == ClientContext.get_volttron_home()


def test_context_in_gevent(create_volttron_home_fun_scope, monkeypatch, undocontext):

    # random volttron_home
    my_original = create_volttron_home_fun_scope

    def in_gevent():
        nonlocal my_original
        changed = "/tmp/volttron/test/t1"
        monkeypatch.setenv("VOLTTRON_HOME", changed)
        with pytest.raises(ValueError):
            ClientContext.get_volttron_home()
        # if we got here then we know we raised an error like it
        # was supposed to happen, so reset the VOLTTRON_HOME back
        # to what it was originally.
        monkeypatch.setenv("VOLTTRON_HOME", my_original)
        # make sure the path didn't get created during this.
        assert not os.path.exists(changed)

    monkeypatch.setenv("VOLTTRON_HOME", my_original)
    original = ClientContext.get_volttron_home()
    assert my_original == original

    glet = gevent.spawn(in_gevent)

    gevent.joinall([glet])
    assert my_original == ClientContext.get_volttron_home()
