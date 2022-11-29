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

from __future__ import annotations

import importlib
import sys
from copy import copy
from pathlib import Path

import mock
import pytest

from volttron.utils import get_class, get_module, get_subclasses

# sys_path_with holds a sys.path that includes the path to
# tests directory on the path.

sys_path_with = copy(sys.path)
sys_path_with.insert(0, str(Path(__file__).parent.parent))


def test_get_module_import_error_raised():
    with pytest.raises(ModuleNotFoundError):
        get_module("non_existing_module.module_data")


def test_get_class_import_error_raised():
    with pytest.raises(ModuleNotFoundError):
        get_class("non_existing_module.module_data", 'SecondaryClass')


def test_get_module():
    with mock.patch('sys.path', sys_path_with):
        module_name = "module_for_testing.module_data"
        actual_module = get_module("module_for_testing.module_data")

        assert actual_module.__name__ == module_name


def test_get_klass_str():
    with mock.patch('sys.path', sys_path_with):
        klass = get_class("module_for_testing.module_data", 'SecondaryClass')
        assert klass.__name__ == 'SecondaryClass'


def test_get_klass_mod():
    with mock.patch('sys.path', sys_path_with):
        module = importlib.import_module("module_for_testing.module_data")
        klass = get_class(module, "MyHelperClass")
        assert klass.__name__ == 'MyHelperClass'


def test_get_klass_attribute_error_raised():
    with pytest.raises(AttributeError) as err:
        get_class("module_for_testing.module_data", 'RandomClass')


def test_get_subclasses_value_error_raised():
    with mock.patch('sys.path', sys_path_with):
        with pytest.raises(ValueError) as err:

            module = importlib.import_module("module_for_testing.module_no_classes_data")
            klass = getattr(importlib.import_module("module_for_testing.module_data"),
                            "MyHelperClass")
            get_subclasses(module, klass)


@pytest.mark.parametrize("return_all, expected_len", [(False, 1), (True, 2)])
def test_get_subclasses_on_all_str(return_all, expected_len):
    with mock.patch('sys.path', sys_path_with):
        expected_subclasses = ['SecondaryClass', 'ThirdClass']
        module = "module_for_testing.module_data"
        parent_class = "MyHelperClass"

        subclasses = get_subclasses(module, parent_class, return_all)

        assert len(subclasses) == expected_len
        for subclass in subclasses:
            assert subclass.__name__ in expected_subclasses


@pytest.mark.parametrize("return_all, expected_len", [(False, 1), (True, 2)])
def test_get_subclasses_on_all_mod(return_all, expected_len):
    with mock.patch('sys.path', sys_path_with):
        expected_subclasses = ['SecondaryClass', 'ThirdClass']
        module = importlib.import_module("module_for_testing.module_data")
        parent_class = getattr(module, "MyHelperClass")

        subclasses = get_subclasses(module, parent_class, return_all=return_all)

        assert len(subclasses) == expected_len
        for subclass in subclasses:
            assert subclass.__name__ in expected_subclasses


@pytest.mark.parametrize("return_all, expected_len", [(False, 1), (True, 2)])
def test_get_subclasses_on_module_str_parent_class_mod(return_all, expected_len):
    with mock.patch('sys.path', sys_path_with):
        expected_subclasses = ['SecondaryClass', 'ThirdClass']
        module = "module_for_testing.module_data"
        parent_class = getattr(importlib.import_module(module), "MyHelperClass")

        subclasses = get_subclasses(module, parent_class, return_all=return_all)

        assert len(subclasses) == expected_len
        for subclass in subclasses:
            assert subclass.__name__ in expected_subclasses


@pytest.mark.parametrize("return_all, expected_len", [(False, 1), (True, 2)])
def test_get_subclasses_on_module_mod_parent_class_str(return_all, expected_len):
    with mock.patch('sys.path', sys_path_with):
        expected_subclasses = ['SecondaryClass', 'ThirdClass']
        module = importlib.import_module("module_for_testing.module_data")
        parent_class = "MyHelperClass"

        subclasses = get_subclasses(module, parent_class, return_all=return_all)

        assert len(subclasses) == expected_len
        for subclass in subclasses:
            assert subclass.__name__ in expected_subclasses
