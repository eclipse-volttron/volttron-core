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
import logging

from volttron.utils.logs import AgentFormatter


def log_to_file(file_, level=logging.WARNING, handler_class=logging.StreamHandler):
    """
    Direct log output to a file (or something like one).
    """
    handler = handler_class(file_)
    handler.setLevel(level)
    handler.setFormatter(
        AgentFormatter(
            fmt="%(asctime)s %(composite_name)s(%(lineno)d) %(levelname)s: %(message)s"))
    root = logging.getLogger()
    if root.level < level:
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
                conf_dict = yaml.load(conf_file)
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
