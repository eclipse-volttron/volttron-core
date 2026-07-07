# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2023 Battelle Memorial Institute
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

"""
Utility functions for prompting users for input.

This module provides reusable functions for common user prompting scenarios
such as password entry, username entry, yes/no questions, and interactive
field prompting.
"""

import collections
import getpass
import sys

_stdout = sys.stdout
_stderr = sys.stderr


def prompt_for_password(prompt_text="Enter password", verify=True):
    """
    Prompt the user for a password.

    :param prompt_text: The text to display when prompting for password
    :param verify: If True, prompt twice and verify passwords match
    :return: The password string
    :raises ValueError: If verify=True and passwords don't match
    """
    while True:
        password = getpass.getpass(f"{prompt_text}: ")

        if not verify:
            return password

        password_confirm = getpass.getpass(f"{prompt_text} (confirm): ")

        if password == password_confirm:
            return password

        _stderr.write("ERROR: Passwords do not match. Please try again.\n")


def prompt_for_username(prompt_text="Enter username", default=None):
    """
    Prompt the user for a username.

    :param prompt_text: The text to display when prompting for username
    :param default: Default value if user presses enter without input
    :return: The username string
    :raises ValueError: If no username is provided and no default
    """
    while True:
        default_str = f" [{default}]" if default else ""
        username = input(f"{prompt_text}{default_str}: ").strip()

        if not username:
            if default:
                return default
            _stderr.write("ERROR: Username cannot be empty.\n")
            continue

        return username


def prompt_yes_no(question, default="yes"):
    """
    Prompt the user for a yes/no answer.

    :param question: The question to ask
    :param default: Default answer if user presses enter ('yes' or 'no')
    :return: True for yes, False for no
    :raises ValueError: If default is not 'yes' or 'no'
    """
    yes_options = {"yes", "ye", "y"}
    no_options = {"no", "n"}

    y_char = "y"
    n_char = "n"

    if default.lower() in yes_options:
        y_char = "Y"
    elif default.lower() in no_options:
        n_char = "N"
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        choice = input(f"{question} [{y_char}/{n_char}] ").lower()

        if choice == "":
            choice = default

        if choice in yes_options:
            return True

        if choice in no_options:
            return False

        _stderr.write("Please respond with 'yes' or 'no'\n")


class InteractiveAsker:
    """
    Generic interactive field prompting system.

    Allows building an interactive questionnaire where users can be prompted
    for multiple fields with custom validation, default values, and callbacks.

    Example:
        asker = InteractiveAsker()
        asker.add("username", default="admin", note="system admin")
        asker.add("enabled", default=True, callback=to_bool, validate=is_bool)
        results = asker.ask()
    """

    def __init__(self):
        """Initialize the asker with empty fields."""
        self._fields = collections.OrderedDict()

    def add(
        self,
        name,
        default=None,
        note=None,
        callback=lambda x: x,
        validate=lambda x, y: (True, ""),
    ):
        """
        Add a field to be prompted for.

        :param name: Field name to display in prompt
        :param default: Default value if user presses enter without input
        :param note: Optional note to display in parentheses in the prompt
        :param callback: Function to transform the response before storing
        :param validate: Function that takes (response, fields_dict) and returns (is_valid, error_msg)
        """
        self._fields[name] = {
            "note": note,
            "default": default,
            "callback": callback,
            "validate": validate,
        }

    def ask(self):
        """
        Prompt the user for all registered fields.

        Returns a dictionary with field names as keys and processed responses as values.
        Validates each response and re-prompts if invalid.

        :return: Dictionary of {field_name: response}
        """
        for name in self._fields:
            note = self._fields[name]["note"]
            default = self._fields[name]["default"]
            callback = self._fields[name]["callback"]
            validate = self._fields[name]["validate"]

            # Format default value for display
            if isinstance(default, list):
                default_str = "{}".format(",".join(default))
            elif default is None:
                default_str = ""
            else:
                default_str = default

            note = "({}) ".format(note) if note else ""
            question = "{} {}[{}]: ".format(name, note, default_str)

            valid = False
            while not valid:
                response = input(question).strip()

                if response == "":
                    response = default

                if response == "clear":
                    if prompt_yes_no("Do you want to clear this field?"):
                        response = None

                valid, msg = validate(response, self._fields)
                if not valid:
                    _stderr.write("{}\n".format(msg))

                self._fields[name]["response"] = callback(response)

        return {k: self._fields[k]["response"] for k in self._fields}
