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

__all__ = ["create_file_if_missing"]

import os
import errno
import logging

_log = logging.getLogger(__name__)


def create_file_if_missing(path, permission=0o660, contents=None):
    dirname = os.path.dirname(path)
    if dirname and not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
    try:
        with open(path) as fd:
            pass
    except IOError as exc:
        if exc.errno != errno.ENOENT:
            raise
        _log.debug("missing file %s", path)
        _log.info("creating file %s", path)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, permission)
        success = False
        try:
            if contents:
                contents = (contents if isinstance(contents, bytes) else contents.encode("utf-8"))
                os.write(fd, contents)
                success = True
        except Exception as e:
            raise e
        finally:
            os.close(fd)
        return success
