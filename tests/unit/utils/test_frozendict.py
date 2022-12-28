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

from volttron.utils.frozendict import FrozenDict


def test_frozen_dict():
    fd = FrozenDict()
    fd.freeze()

    with pytest.raises(TypeError) as ex:
        fd["foo"] = "bar"

    assert "foo" not in fd.keys()
    assert "Attempted assignment to a frozen dict" == ex.value.args[0]

    # TODO handle htis case.
    # fd.update({"alpha": "beta"})

    # print(list(fd.keys()))
    # assert 1 == len(list(fd.keys()))

    # assert 'alpha' not in list(fd.keys())
    # assert 'foo' in list(fd.keys())
