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
from zmq.sugar.frame import Frame
from volttron.utils.frame_serialization import (
    deserialize_frames,
    serialize_frames,
)


def test_can_deserialize_homogeneous_string():
    abc = ["alpha", "beta", "gamma"]
    frames = [Frame(x.encode("utf-8")) for x in abc]

    deserialized = deserialize_frames(frames)

    for r in range(len(abc)):
        assert abc[r] == deserialized[r], f"Element {r} is not the same."


def test_can_serialize_homogeneous_strings():
    original = ["alpha", "beta", "gamma"]
    frames = serialize_frames(original)

    for r in range(len(original)):
        assert original[r] == frames[r].bytes.decode(
            "utf-8"), f"Element {r} is not the same."


def test_mixed_array():
    original = [
        "alpha",
        dict(alpha=5, gamma="5.0", theta=5.0),
        "gamma",
        ["from", "to", "VIP1", ["third", "level", "here", 50]],
    ]
    frames = serialize_frames(original)
    for x in frames:
        assert isinstance(x, Frame)

    after_deserialize = deserialize_frames(frames)

    for r in range(len(original)):
        assert original[r] == after_deserialize[
            r], f"Element {r} is not the same."
