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

import pytest

from volttron.utils.math_utils import (mean, pstdev, stdev)


@pytest.mark.parametrize("data, expected", [([1, 7, 10], 6.0), ([1, 2, 3, 4], 2.5), ([42], 42.0)])
def test_mean_should_succeed(data, expected):
    assert mean(data) == expected


def test_mean_should_raise_value_error():
    with pytest.raises(ValueError) as excinfo:
        mean([])

    assert str(excinfo.value) == 'mean requires at least one data point'


@pytest.mark.parametrize("data, expected", [
    ([2, 4], 1.0),
    ([1, 2, 3, 4, 5], 1.4142135623731),
    ([0, 0], 0.0),
])
def test_pstdev_should_succeed(data, expected):
    assert pstdev(data) == pytest.approx(expected, rel=1e-3)


@pytest.mark.parametrize("invalid_data", [([]), ([42])])
def test_pstdev_should_raise_value_error(invalid_data):
    with pytest.raises(ValueError) as excinfo:
        pstdev(invalid_data)

    assert str(excinfo.value) == 'variance requires at least two data points'


@pytest.mark.parametrize("data, expected", [
    ([2, 4], 1.414),
    ([1, 2, 3, 4, 5], 1.5811388300842),
    ([0, 0], 0.0),
])
def test_stdev_should_succeed(data, expected):
    assert stdev(data) == pytest.approx(expected, rel=1e-3)


@pytest.mark.parametrize("invalid_data", [([]), ([42])])
def test_stdev_should_raise_value_error(invalid_data):
    with pytest.raises(ValueError) as excinfo:
        stdev(invalid_data)

    assert str(excinfo.value) == 'variance requires at least two data points'
