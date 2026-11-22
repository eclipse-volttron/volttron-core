# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2026 Battelle Memorial Institute
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
"""Command-line helpers on the public argparse API only (volttron-core#306).

The server and vctl used to subclass ``argparse.ArgumentParser`` and patch argparse internals, which broke with each
Python release that changed those internals (3.11, 3.12.7, 3.13). Everything here uses documented API:

- :class:`AddConstAction` adds a constant to the destination each time the option appears (``-v``/``-q``);
- :func:`config_args` turns a config file into command-line arguments, which the caller places before its own, so
  the command line wins for single values and lists such as ``--address`` combine, config first.
"""
from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Iterable, Iterator, NamedTuple, Sequence

__all__ = ["AddConstAction", "ConfigSetting", "config_args", "expandall", "read_config", "as_bool"]

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def expandall(string: str) -> str:
    """Expand ``~`` and environment variables."""
    return os.path.expanduser(os.path.expandvars(string))


def as_bool(value) -> bool:
    """A config or command-line boolean: a bool, or one of 1/0, true/false, yes/no, on/off (any case)."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"not a boolean: {value!r}")


class AddConstAction(argparse.Action):
    """Add ``const`` to the destination each time the option is given (``-v`` lowers the level by 10, ``-q`` raises
    it). Combined short options count each letter: ``-vvq`` is two ``-v`` and one ``-q``."""

    def __init__(self, option_strings, dest, const, default=None, required=False, help=None, metavar=None):
        super().__init__(option_strings=option_strings, dest=dest, nargs=0, const=const, default=default,
                         required=required, help=help, metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        current = getattr(namespace, self.dest, None)
        if current is None or current is argparse.SUPPRESS:
            current = self.default if isinstance(self.default, int) else 0
        setattr(namespace, self.dest, current + self.const)


class ConfigSetting(NamedTuple):
    section: str | None
    key: str
    value: str | None    # None for a bare key, which means "true"
    lineno: int


_SECTION = re.compile(r"^\[\s*(?P<name>[^\]]*?)\s*\]\s*$")
_SETTING = re.compile(r"^(?P<key>[^=:\s]+)\s*(?:[=:]\s*(?P<value>.*?))?\s*$")


def read_config(path: str | Path) -> Iterator[ConfigSetting]:
    """The settings of an INI-style config file in order: one ``key = value`` (or ``key: value``, or a bare ``key``)
    per line; ``#`` and ``;`` start comments at the start of a line or after whitespace; a key may repeat (``address``).
    Raises ``ValueError`` with the line number for a line that is neither."""
    section = None
    for lineno, raw in enumerate(Path(path).read_text().splitlines(), start=1):
        line = re.split(r"(?:^|\s)[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        match = _SECTION.match(line)
        if match:
            section = match.group("name")
            continue
        match = _SETTING.match(line)
        if not match:
            raise ValueError(f"{path} (line {lineno}): cannot parse {raw.strip()!r}")
        value = match.group("value")
        yield ConfigSetting(section, match.group("key"), value, lineno)


def _takes_no_value(action: argparse.Action) -> bool:
    return action.nargs == 0


def config_args(parser: argparse.ArgumentParser, path: str | Path, *, sections: Sequence[str | None] = (None, ),
                strict: bool = True, exclude: Iterable[str] = ("help", "version", "config")) -> list[str]:
    """Command-line arguments equivalent to the config file's settings, for ``parser``.

    Keys are long option names without the dashes (``instance-name``; ``instance_name`` works too). Only settings in
    ``sections`` are used (``None`` is the part before any section header). A flag with a false value becomes its
    inverse option when the parser has one (``enable-federation = False`` becomes ``--disable-federation``: the
    ``store_false`` option with the same destination) and is otherwise skipped. With ``strict``, an unknown key, an
    excluded key or a value that does not suit the option is a ``parser.error`` naming the file, line and key;
    without it those settings are skipped.
    """
    options = {}
    for action in _actions(parser):
        for option in action.option_strings:
            if option.startswith("--"):
                options[option[2:]] = action
    excluded = set(exclude)
    args: list[str] = []

    def fail(setting, message):
        if strict:
            parser.error(f"{path} (line {setting.lineno}): {message}: {setting.key}")

    try:
        settings = list(read_config(path))
    except ValueError as e:
        parser.error(str(e))
    for setting in settings:
        if setting.section not in sections:
            continue
        key = setting.key.lstrip("-").replace("_", "-")
        action = options.get(key)
        if action is None:
            fail(setting, "unknown option")
            continue
        if key in excluded or action.dest in excluded:
            fail(setting, "option not allowed in a config file")
            continue
        option = f"--{key}"
        if _takes_no_value(action):
            try:
                on = True if setting.value is None or setting.value == "" else as_bool(setting.value)
            except ValueError:
                fail(setting, "option expects a boolean")
                continue
            if on:
                args.append(option)
            else:
                inverse = _inverse(parser, action)
                if inverse:
                    args.append(inverse)
        else:
            if setting.value is None:
                fail(setting, "option expects a value")
                continue
            args += [option, setting.value]
    return args


def _actions(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    # ``parser._actions`` is the one internal argparse attribute this module reads; it has been stable since
    # Python 2.7 and there is no public way to list a parser's options.
    return list(parser._actions)


def _inverse(parser: argparse.ArgumentParser, action: argparse.Action) -> str | None:
    """The long option that undoes a store_true flag: a store_false option with the same destination."""
    if not (action.nargs == 0 and action.const is True):     # store_true
        return None
    for other in _actions(parser):
        if other is not action and other.dest == action.dest and other.nargs == 0 and other.const is False:
            longs = [o for o in other.option_strings if o.startswith("--")]
            if longs:
                return longs[0]
    return None
