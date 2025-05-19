from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import sys
import traceback
from pathlib import Path
from typing import List, Type
import ast
import os

__all__: List[str] = ["load_dir", "load_subclasses", "find_subpackages"]

_log = logging.getLogger(__name__)

__loaded__: set[str] = set()


def is_subclass(node, base_class_name):
    # Check if the node is a class that derives from the given base class
    return (
            isinstance(node, ast.ClassDef) and
            any(base.id == base_class_name for base in node.bases if isinstance(base, ast.Name))
    )


def find_subpackages(base_package_name):
    subpackages = set()

    # Iterate over every path in sys.path
    for path in sys.path:
        if not path or not isinstance(path, str):
            continue

        potential_package_path = os.path.join(path, *base_package_name.split('.'))

        if os.path.isdir(potential_package_path):
            for root, dirs, files in os.walk(potential_package_path):
                # Determine if it's a package by checking for __init__.py presence
                if '__init__.py' in files:
                    # Calculate the relative module path
                    rel_path = os.path.relpath(root, path)
                    package_name = rel_path.replace(os.sep, '.')
                    subpackages.add(package_name)

    return subpackages


def load_subclasses(base_class_with_package, package):
    """
    Given a base class (ex. volttron.types.MessageBus) return the concrete subclass available in
    path(example ZMQMessageBus).
    This assumes that the subclass in a package package_prefix.* For example ZMQMessageBus should be defined in a
    module within some package that starts with volttron.messagebus
    The code uses static loading to inspect all existing modules under package_prefix.* and imports only the
    module containing the subclasses of given base class. This is done to avoid importing all modules in the packages
    there by avoiding modules with blocking top level code such as while True: loop

    :param base_class_with_package: Baseclass name with package. Example: volttron.types.MessageBus
    :param package: prefix of package where to expect concrete implementation. Example: volttron.messagebus
    :return: set of subclasses
    """

    #import the base class
    module = base_class_with_package[:base_class_with_package.rindex(".")]
    m = importlib.import_module(module)
    base_class = getattr(m, base_class_with_package[base_class_with_package.rindex(".") + 1:])

    package_mod = importlib.import_module(package)
    package_path = package_mod.__path__
    package_path = package_path[0]
    base_class_name = base_class.__name__
    subclasses = set()

    for root, _, files in os.walk(package_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)

                # Skip __init__.py in module name conversion
                if file == '__init__.py':
                    module_name = root.replace(os.sep, '.')
                else:
                    module_name = file_path.replace(os.sep, '.')[:-3]  # Convert path to module format
                module_name = module_name[module_name.index(package):]  # Adjust to get full package name

                with open(file_path, 'r') as source_file:
                    try:
                        tree = ast.parse(source_file.read(), filename=file_path)

                        for node in ast.walk(tree):
                            if is_subclass(node, base_class_name):
                                module = importlib.import_module(module_name)
                                for name, obj in inspect.getmembers(module, inspect.isclass):
                                    if issubclass(obj, base_class) and obj is not base_class:
                                        subclasses.add(obj)
                    except SyntaxError as e:
                        print(f"Syntax error in file {file_path}: {e}")

    return subclasses


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
        # print(globals())
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

            # assert new_package in globals()
            if p.is_dir():
                load_dir(new_package, p)
