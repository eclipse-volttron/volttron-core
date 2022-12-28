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

__all__ = ["get_version"]

from pathlib import Path
import importlib.metadata as importlib_metadata

# Try to get the version from written metadata, but
# if failed then get it from the pyproject.toml file
try:
    # Note this is the wheel prefix or the name attribute in pyproject.toml file.
    # this is the version of the program that is used when the application is installed
    # via a wheel.
    __version__ = importlib_metadata.version('volttron')
except importlib_metadata.PackageNotFoundError:
    # We should be in a develop environment therefore
    # we can get the version from the toml pyproject.toml
    root = Path(__file__).parent.parent.parent
    tomle_file = root.joinpath("pyproject.toml")
    if not tomle_file.exists():
        raise ValueError(
            f"Couldn't find pyproject.toml file for finding version. ({str(tomle_file)})")
    import toml

    pyproject = toml.load(tomle_file)

    __version__ = pyproject["tool"]["poetry"]["version"]


def get_version():
    """
    Return the version number of the platform.  This function handles both cases where
    we are in developer mode (i.e. there is a pyproject.toml file) and when it is
    installed in a deployed environment where the version is looked up from the parent.
    """
    return __version__
