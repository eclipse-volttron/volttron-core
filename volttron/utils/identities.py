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


__all__ = ["is_valid_identity", "normalize_identity"]

import re

# The following are the only allowable characters for identities.
_VALID_IDENTITY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def is_valid_identity(identity_to_check):
    """Checks the passed identity to see if it contains invalid characters

    A None value for identity_to_check will return False

    @:param: string: The vip_identity to check for validity
    @:return: boolean: True if values are in the set of valid characters.
    """

    if identity_to_check is None:
        return False

    return _VALID_IDENTITY_RE.match(identity_to_check)


def normalize_identity(pre_identity):
    if is_valid_identity(pre_identity):
        return pre_identity

    if pre_identity is None:
        raise ValueError("Identity cannot be none.")

    norm = ""
    for s in pre_identity:
        if _VALID_IDENTITY_RE.match(s):
            norm += s
        else:
            norm += "_"

    return norm
