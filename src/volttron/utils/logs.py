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

import logging
import os
import stat
import sys
import syslog
import traceback
import warnings

from volttron.utils import jsonapi

try:
    HAS_SYSLOG = True
    import syslog
except ImportError:
    HAS_SYSLOG = False

# Keep the ability to have system log output for linux
# this will fail on windows because no syslog.
if HAS_SYSLOG:

    class SyslogFormatter(logging.Formatter):
        _level_map = {
            logging.DEBUG: syslog.LOG_DEBUG,
            logging.INFO: syslog.LOG_INFO,
            logging.WARNING: syslog.LOG_WARNING,
            logging.ERROR: syslog.LOG_ERR,
            logging.CRITICAL: syslog.LOG_CRIT,
        }

        def format(self, record):
            level = self._level_map.get(record.levelno, syslog.LOG_INFO)
            return "<{}>".format(level) + super(SyslogFormatter, self).format(record)


def isapipe(fd):
    fd = getattr(fd, "fileno", lambda: fd)()
    return stat.S_ISFIFO(os.fstat(fd).st_mode)


class JsonFormatter(logging.Formatter):

    def format(self, record):
        dct = record.__dict__.copy()
        dct["msg"] = record.getMessage()
        dct.pop("args")
        exc_info = dct.pop("exc_info", None)
        if exc_info:
            dct["exc_text"] = "".join(traceback.format_exception(*exc_info))
        return jsonapi.dumps(dct)


class AgentFormatter(logging.Formatter):

    def __init__(self, fmt=None, datefmt=None):
        if fmt is None:
            fmt = "%(asctime)s %(composite_name)s %(levelname)s: %(message)s"
        super(AgentFormatter, self).__init__(fmt=fmt, datefmt=datefmt)

    def composite_name(self, record):
        if record.name == "agents.log":
            cname = "(%(processName)s %(process)d) %(remote_name)s"
        elif record.name.startswith("agents.std"):
            cname = "(%(processName)s %(process)d) <{}>".format(record.name.split(".", 2)[1])
        else:
            cname = "() %(name)s"
        return cname % record.__dict__

    def format(self, record):
        if "composite_name" not in record.__dict__:
            record.__dict__["composite_name"] = self.composite_name(record)
        return super(AgentFormatter, self).format(record)


class FramesFormatter(object):

    def __init__(self, frames):
        self.frames = frames

    def __repr__(self):
        output = ''
        for f in self.frames:
            output += str(f)
        return output

    __str__ = __repr__


def log_to_file(file, level=logging.WARNING, handler_class=logging.StreamHandler):
    """Direct log output to a file (or something like one)."""
    handler = handler_class(file)
    handler.setLevel(level)
    handler.setFormatter(
        AgentFormatter("%(asctime)s %(composite_name)s %(levelname)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


def setup_logging(level=logging.DEBUG, console=False):
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()

        if isapipe(sys.stderr) and "_LAUNCHED_BY_PLATFORM" in os.environ:
            handler.setFormatter(JsonFormatter())
        elif console:
            # Below format is more readable for console
            handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        else:
            fmt = "%(asctime)s %(name)s %(levelname)s: %(message)s"
            handler.setFormatter(logging.Formatter(fmt))
        if level != logging.DEBUG:
            # import it here so that when urllib3 imports the requests package, ssl would already got
            # monkey patched by gevent.
            # and this warning is needed only when log level is not debug
            from urllib3.exceptions import InsecureRequestWarning

            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        root.addHandler(handler)
    root.setLevel(level)
