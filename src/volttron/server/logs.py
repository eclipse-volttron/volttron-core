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
import hashlib
import inspect
import logging
import logging.config
import os
import re
import stat
import syslog
import traceback
from logging import FileHandler
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Set

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


DEFAULT_LOG_TAIL = 200
DEFAULT_LOG_BYTES = 65536
MAX_LOG_BYTES = 1048576
MAX_LOG_TAIL = 10000


def _is_log_name(filename: str, base_name: str) -> bool:
    return filename == base_name or bool(re.fullmatch(re.escape(base_name) + r"\.\d+", filename))


def _log_file_candidates(volttron_home: Optional[str] = None) -> Set[str]:
    paths: Set[str] = set()
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            filename = os.path.abspath(handler.baseFilename)
            if os.path.isfile(filename):
                paths.add(filename)
    if volttron_home and os.path.isdir(volttron_home):
        for entry in os.listdir(volttron_home):
            if entry.endswith(".log") or ".log." in entry:
                path = os.path.abspath(os.path.join(volttron_home, entry))
                if os.path.isfile(path):
                    paths.add(path)
    return paths


def _hash_file_identity(st_dev: int, st_ino: int) -> str:
    """Hash device and inode to create an opaque, stable file identifier for rotation detection without leaking raw inode info."""
    return hashlib.sha256(f"{st_dev}:{st_ino}".encode("utf-8")).hexdigest()[:16]


def _hash_log_id(filename: str) -> str:
    """Generate a deterministic neutral identifier from filename."""
    return hashlib.sha256(filename.encode("utf-8")).hexdigest()[:16]


def get_log_retention() -> Optional[Dict[str, Any]]:
    for handler in logging.getLogger().handlers:
        if isinstance(handler, RotatingFileHandler):
            max_bytes = handler.maxBytes
            backups = handler.backupCount
            if max_bytes > 0:
                return {
                    "max_file_bytes": max_bytes,
                    "backup_count": backups,
                    "max_total_bytes": max_bytes * (backups + 1),
                }
    return None


def get_available_logs(volttron_home: Optional[str] = None) -> Dict[str, Any]:
    discovered = {}
    for base_path in _log_file_candidates(volttron_home):
        directory = os.path.dirname(base_path)
        base_name = os.path.basename(base_path)
        try:
            filenames = os.listdir(directory)
        except OSError:
            continue
        for filename in filenames:
            if _is_log_name(filename, base_name):
                path = os.path.join(directory, filename)
                if os.path.isfile(path):
                    try:
                        stat_res = os.stat(path)
                    except OSError:
                        continue
                    log_id = _hash_log_id(filename)
                    discovered[filename] = {
                        "id": log_id,
                        "name": filename,
                        "file_id": _hash_file_identity(stat_res.st_dev, stat_res.st_ino),
                        "size_bytes": stat_res.st_size,
                        "modified": stat_res.st_mtime,
                        "is_active": filename == base_name,
                    }
    logs_list = sorted(discovered.values(), key=lambda item: item["name"])
    return {
        "logs": logs_list,
        "retention": get_log_retention(),
    }


def read_log_file(
    log_id: str,
    tail: int = DEFAULT_LOG_TAIL,
    offset: Optional[int] = None,
    before: Optional[int] = None,
    max_bytes: int = DEFAULT_LOG_BYTES,
    volttron_home: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Read a bounded portion of a discovered log file.

    Parameters:
    - log_id: Neutral ID (SHA-256 prefix) or safe filename of the log file.
    - tail: Number of lines to return from end of file (used when offset and before are None).
    - offset: Byte offset to read forward from (used for live streaming/following).
    - before: Byte offset to read backwards from (used for reverse historical pagination).
    - max_bytes: Maximum number of bytes to read in one request (capped at 1 MiB).
    - volttron_home: Optional path to VOLTTRON home directory.
    """
    discovered_info = get_available_logs(volttron_home)
    available_logs = discovered_info.get("logs", [])

    matched_item = None
    for item in available_logs:
        if item["id"] == log_id or item["name"] == log_id:
            matched_item = item
            break

    if matched_item is None:
        raise FileNotFoundError(f"Log not found: {log_id}")

    target_filename = matched_item["name"]
    base_path = next(
        (path for path in _log_file_candidates(volttron_home) if _is_log_name(target_filename, os.path.basename(path))),
        None,
    )
    if base_path is None:
        raise FileNotFoundError(f"Log not found: {log_id}")

    path = os.path.join(os.path.dirname(base_path), target_filename)
    stat_res = os.stat(path)
    file_size = stat_res.st_size
    file_id = matched_item["file_id"]
    canonical_id = matched_item["id"]
    max_bytes = min(max(1, max_bytes), MAX_LOG_BYTES)

    with open(path, "rb") as log_file:
        if before is not None:
            before = min(max(0, before), file_size)
            start = max(0, before - max_bytes)
            log_file.seek(start)
            chunk = log_file.read(before - start)
            previous_offset = start
            if start and chunk:
                log_file.seek(start - 1)
                begins_mid_line = log_file.read(1) != b"\n"
            else:
                begins_mid_line = False
            if begins_mid_line:
                first_newline = chunk.find(b"\n")
                if first_newline >= 0:
                    previous_offset = start + first_newline + 1
                    chunk = chunk[first_newline + 1:]
            end_offset = before
            if before < file_size and chunk:
                log_file.seek(before - 1)
                ends_mid_line = log_file.read(1) != b"\n"
                if ends_mid_line:
                    last_newline = chunk.rfind(b"\n")
                    if last_newline >= 0:
                        chunk = chunk[:last_newline + 1]
                        end_offset = previous_offset + len(chunk)
            return {
                "lines": chunk.decode("utf-8", errors="replace").splitlines(),
                "start_offset": previous_offset,
                "end_offset": end_offset,
                "previous_offset": previous_offset,
                "next_offset": end_offset,
                "total_bytes": file_size,
                "file_id": file_id,
                "log_id": canonical_id,
                "has_older": previous_offset > 0,
                "has_newer": before < file_size,
            }

        if offset is None:
            start = max(0, file_size - max_bytes)
            log_file.seek(start)
            chunk = log_file.read(max_bytes)
            if start:
                first_newline = chunk.find(b"\n")
                if first_newline >= 0:
                    chunk = chunk[first_newline + 1:]
            lines = chunk.decode("utf-8", errors="replace").splitlines()
            return {
                "lines": lines[-min(max(1, tail), MAX_LOG_TAIL):],
                "start_offset": start,
                "next_offset": file_size,
                "previous_offset": start,
                "total_bytes": file_size,
                "file_id": file_id,
                "log_id": canonical_id,
                "has_older": start > 0,
                "has_newer": False,
            }

        offset = max(0, offset)
        if offset >= file_size:
            return {
                "lines": [],
                "start_offset": file_size,
                "next_offset": file_size,
                "previous_offset": offset,
                "total_bytes": file_size,
                "file_id": file_id,
                "log_id": canonical_id,
                "has_older": offset > 0,
                "has_newer": False,
            }

        log_file.seek(offset)
        chunk = log_file.read(max_bytes)
        next_offset = log_file.tell()
        if chunk and not chunk.endswith(b"\n") and next_offset < file_size:
            partial_start = chunk.rfind(b"\n") + 1
            next_offset = offset + partial_start
            chunk = chunk[:partial_start]

        return {
            "lines": chunk.decode("utf-8", errors="replace").splitlines(),
            "start_offset": offset,
            "next_offset": next_offset,
            "previous_offset": offset,
            "total_bytes": file_size,
            "file_id": file_id,
            "log_id": canonical_id,
            "has_older": offset > 0,
            "has_newer": next_offset < file_size,
        }

