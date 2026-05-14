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

import argparse
import inspect
import logging
import logging.config
import os
import stat
import syslog
import traceback

from pathlib import Path

from volttron.utils import jsonapi
from volttron.client.logs import AgentFormatter

try:
    HAS_SYSLOG = True
    import syslog
except ImportError:
    HAS_SYSLOG = False

# Keep the ability to have system log output for linux this will fail on Windows because no syslog.
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


__enable_trace__ = False


def enable_trace():
    global __enable_trace__
    __enable_trace__ = True


def disable_trace():
    global __enable_trace__
    __enable_trace__ = False


def logtrace(func: callable, *args, **kwargs):
    """
    Decorator that logs the function call and return value.

    Example:
        @logtrace
        def add(a, b):
            return a + b

        add(2, 3)
        # Output in debug log:
        # add(a, b) called with (2, 3), {}
        # add returned: 5

    @param func: The function to be decorated.
    @type func: callable
    @return: The decorated function.
    @rtype: callable
    """
    enabled = kwargs.pop('enabled', False)
    logger = logging.getLogger(func.__module__)
    sig = inspect.signature(func)

    def do_logging(*args, **kwargs):
        if __enable_trace__:
            logger.debug(f"-->{func.__name__}{sig} called with {args}, {kwargs}")
        ret = func(*args, **kwargs)
        if __enable_trace__:
            logger.debug(f"<--{func.__name__} returned: {ret}")
        return ret

    return do_logging


class JsonFormatter(logging.Formatter):

    def format(self, record):
        dct = record.__dict__.copy()
        dct["msg"] = record.getMessage()
        dct.pop("args")
        exc_info = dct.pop("exc_info", None)
        if exc_info:
            dct["exc_text"] = "".join(traceback.format_exception(*exc_info))
        return jsonapi.dumps(dct)


class FramesFormatter(object):

    def __init__(self, frames):
        self.frames = frames

    def __repr__(self):
        output = ''
        for f in self.frames:
            output += str(f)
        return output

    __str__ = __repr__

def log_to_console(level=logging.WARNING, handler_class=logging.StreamHandler, *args, **kwargs):
    handler = handler_class(*args, **kwargs)
    handler.setLevel(level)
    handler.setFormatter(AgentFormatter(fmt="%(asctime)s %(composite_name)s(%(lineno)d) %(levelname)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

def log_to_file(file_, level=logging.WARNING, handler_class=logging.StreamHandler):
    """
    Direct log output to a file (or something like one).
    """
    if issubclass(handler_class, logging.FileHandler):
        os.makedirs(Path(file_).parent, exist_ok=True)
    handler = handler_class(file_) if handler_class is not logging.NullHandler else handler_class()
    handler.setLevel(level)
    handler.setFormatter(AgentFormatter(fmt="%(asctime)s %(composite_name)s(%(lineno)d) %(levelname)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

def configure_logging(conf_path):
    """
    Load logging configuration from a file.

    Several formats are possible: ini, JSON, Python, and YAML. The ini
    format uses the standard Windows ini file format and is read in
    using logging.config.fileConfig(). The remaining formats will be
    read in according to the serialization format and the resulting
    dictionary will be passed to logging.config.dictConfig(). See the
    logging.config module for specifics on the two file and dict
    formats. Returns None on success, (path, exception) on error.

    The default format is ini. Other formats will be selected based on
    the file extension. Each format can be forced, regardless of file
    extension, by prepending the path with the format name followed by a
    colon:

      Examples:
        config.json        is loaded as JSON
        config.conf        is loaded as ini
        json:config.conf   is loaded as JSON

    YAML formatted configuration files require the PyYAML package.
    """
    if isinstance(conf_path, Path):
        conf_path = conf_path.as_posix()

    conf_format = "ini"
    if conf_path.startswith("ini:"):
        conf_format, conf_path = "ini", conf_path[4:]
    elif conf_path.startswith("json:"):
        conf_format, conf_path = "json", conf_path[5:]
    elif conf_path.startswith("py:"):
        conf_format, conf_path = "py", conf_path[3:]
    elif conf_path.startswith("yaml:"):
        conf_format, conf_path = "yaml", conf_path[5:]
    elif conf_path.endswith(".json"):
        conf_format = "json"
    elif conf_path.endswith(".py"):
        conf_format = "py"
    elif conf_path.endswith(".yaml"):
        conf_format = "yaml"
    elif conf_path.endswith(".yml"):
        conf_format = "yaml"

    if conf_format == "ini":
        try:
            logging.config.fileConfig(conf_path)
        except (ValueError, TypeError, AttributeError, ImportError) as exc:
            return conf_path, exc
        return

    with open(conf_path) as conf_file:
        if conf_format == "json":
            try:
                conf_dict = jsonapi.load(conf_file)
            except ValueError as exc:
                return conf_path, exc
        elif conf_format == "py":
            import ast

            try:
                conf_dict = ast.literal_eval(conf_file.read())
            except ValueError as exc:
                return conf_path, exc
        else:
            try:
                import yaml
            except ImportError:
                return (
                    conf_path,
                    "PyYAML must be installed before "
                    "loading logging configuration from a YAML file.",
                )
            try:
                expanded_conf = os.path.expanduser(os.path.expandvars(conf_file.read()))
                conf_dict = yaml.safe_load(expanded_conf)
            except yaml.YAMLError as exc:
                return conf_path, exc
    try:
        logging.config.dictConfig(conf_dict)
    except (ValueError, TypeError, AttributeError, ImportError) as exc:
        return conf_path, exc


class LogLevelAction(argparse.Action):
    """
    Action to set the log level of individual modules.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        for pair in values.split(","):
            if not pair.strip():
                continue
            try:
                logger_name, level_name = pair.rsplit(":", 1)
            except (ValueError, TypeError):
                raise argparse.ArgumentError(self, "invalid log level pair: {}".format(values))
            try:
                level = int(level_name)
            except (ValueError, TypeError):
                try:
                    level = getattr(logging, level_name)
                except AttributeError:
                    raise argparse.ArgumentError(self, "invalid log level {!r}".format(level_name))
            logger = logging.getLogger(logger_name)
            logger.setLevel(level)
