from __future__ import annotations

import importlib
import inspect
import logging
import sys
import traceback
from pathlib import Path
from types import ModuleType
from typing import List, Type

from volttron.utils import logtrace

__all__: List[str] = ["get_module", "get_class", "get_subclasses", "load_dir"]

_log = logging.getLogger(__name__)

__loaded__: set[str] = set()


@logtrace
def load_dir(package: str, pth: Path):
    """
    Recursively loads all modules within a directory.

    :param package: The package name.
    :type package: str
    :param pth: The path to the directory.
    :type pth: :class:`pathlib.Path`

    This function recursively loads all modules within the specified directory. It iterates
    over the files and subdirectories in the directory, imports each module, and loads any
    subdirectories as sub-packages.

    If a file is a Python source file (`.py`), it is imported as a module. If a file is a
    directory, it is loaded as a sub-package.

    Example usage::

        load_dir('volttron', Path('/path/to/directory'))

    .. note::
        This function does not load compiled Python files (`.pyc`) or files in
        the `__pycache__` directory.

    .. warning::
        Be cautious when using this function, as it imports and loads all modules within a
        directory, which may have unintended side effects.
    """

    # Find the caller of this function
    caller_module = inspect.currentframe().f_back.f_globals["__name__"]

    get_mod_name = lambda pth: pth.name if pth.is_dir() else pth.stem

    # We only want to load from py files rather than pyc files
    # so filter
    for p in filter(lambda x: x.name != '__pycache__', pth.iterdir()):

        new_package = f"{package}.{get_mod_name(p)}"

        if new_package.endswith("__init__") or new_package.endswith('.mypy_cache'):
            _log.debug(f"Skipping {new_package}")
            continue

        if f"{caller_module}.__init__" == new_package:
            _log.debug(f"Skipping {new_package}")
            continue
        #print(globals())
        if p.absolute().as_posix() not in __loaded__:
            __loaded__.add(p.absolute().as_posix())
            _log.debug(f"Loading {new_package}")
            try:
                importlib.import_module(new_package)
            except ImportError as ex:
                traceback.print_exc()
                _log.error(f"Failed to import {new_package} due to {ex}")
                raise
                continue
            # after = set(globals().keys())
            # print("After import")
            # print(before - after)
            # print("AFTER!!!!")
            # for k in list(globals().keys()):
            #     print(k)

            #assert new_package in globals()
            if p.is_dir():
                load_dir(new_package, p)
