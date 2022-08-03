from __future__ import annotations

import importlib
import inspect
import logging
from types import ModuleType
from typing import List, Type

<<<<<<< HEAD
__all__: List[str] = ["get_module", "get_class", "get_subclasses"]
=======
__all__: List[str] = ["get_klass", "get_subclasses", "get_module"]
>>>>>>> test dynamic helper

_log = logging.getLogger(__name__)


def get_module(module: str) -> ModuleType:
<<<<<<< HEAD
    """Returns a dynamically loaded module. If not found on pythonpath, then raise a ModuleNotFound error.
    This method is a wrapper around Python's builtin function, importlib.import_module(...).
    See https://docs.python.org/3/library/importlib.html#importlib.import_module

    :param module: The name argument specifies what module to import in absolute or relative terms (e.g. either pkg.mod or ..mod).
        If the name is specified in relative terms, then the package argument must be set to the name of the package which is to act as the
        anchor for resolving the package name (e.g. import_module('..mod', 'pkg.subpkg') will import pkg.mod).
    :type module: str
    :raises ModuleNotFoundError:
    :return: A module
    :rtype: ModuleType
    """
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError as e:
        _log.debug(f"Module: {module} not found. Make sure it is on the PYTHONPATH")
        raise e


def get_class(module: str | ModuleType, class_name: str) -> Type:
    """Retrieve a Type from a module. If module is a string, attempt to load it via importlib.import_module.
    If not a string, then directly look for a class within the passed module.

    :param module: the path to a module or the actual module
    :type module: str | ModuleType
    :param class_name: the name of the type in the module
    :type class_name: str
    :raises AttributeError:
    :return: Returns the class from the module
    :rtype: Type
    """
    try:
        if isinstance(module, str):
            return getattr(get_module(module), class_name)
        return getattr(module, class_name)
    except AttributeError as e:
        _log.debug(f"Class {class_name} is not defined in {module}.")
        raise e


def get_subclasses(module: ModuleType | str,
                   parent_class: Type | str,
                   return_all=False) -> List[Type]:
    """Returns a list of subclasses of a specific type. If return_all is set to True,
    returns all subclasses, otherwise return a list with only the first subclass found.

    :param module: A module containing classes
    :type module: ModuleType | str
    :param parent_class: The parent class that could be a parent of classes in the module
    :type parent_class: Type | str
    :param return_all: True if all subclasses are desired; False if only the first subclass. Defaults to False
    :type return_all: bool, optional
    :raises ValueError: Raises ValueError if no subclasses are found.
    :return: A list of sublcasses of a specific type
    :rtype: List
    """
    all_subclasses = []

    if isinstance(module, str):
        module = importlib.import_module(module)
    if isinstance(parent_class, str):
        parent_class = getattr(module, parent_class)
    for c in inspect.getmembers(module, inspect.isclass):
        if parent_class in c[1].__bases__:
            all_subclasses.append(c[1])
            if not return_all:
                break

    if not all_subclasses:
        raise ValueError(f"No subclass of {parent_class} found in {module.__name__}")
=======
    """
    Get a dynamically loaded module using importlib.  If not found on pythonpath then
    raise a ModuleNotFound error.
    """
    try:
        module_base = importlib.import_module(module)
    except ModuleNotFoundError as e:
        _log.debug(f"Module: {module} not found.  Make sure it is on the pythonpath")
        raise e

    return module_base


def get_klass(module: str | ModuleType, klass_name: str) -> Type:
    """
    Retrieve a Type from a module.

    If module is a string, attempt to load it via importlib.import_module.  If not a string
    then directly look for a class within the passed module.

    This method will raise ModuleNotFoundError if the passed module is not on the system path.
    """

    try:
        if isinstance(module, str):
            module_base = importlib.import_module(module)
        else:
            module_base = module
    except ModuleNotFoundError as e:
        _log.debug(f"Volttron-lib-driver was not installed. Cannot find Driver modules: {e}")
        raise e

    klass_interface = getattr(module_base, klass_name)

    _log.debug(f"Interface for {klass_name} interface: {klass_interface}")

    return klass_interface


def get_subclasses(module: ModuleType, parent_klass: Type, return_all=False) -> List[Type]:
    """
    Determine and return subclasses of a specific type.
    """
    all_subclasses = []
    for c in inspect.getmembers(module, inspect.isclass):
        if parent_klass in c[1].__bases__:
            all_subclasses.append(c[1])
            if not return_all:
                break
    if not all_subclasses:
        raise ValueError(f"No subclass of {parent_klass} found in {module.__name__}")
>>>>>>> test dynamic helper

    return all_subclasses
