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
        assert original[r] == frames[r].bytes.decode("utf-8"), f"Element {r} is not the same."


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
        assert original[r] == after_deserialize[r], f"Element {r} is not the same."
