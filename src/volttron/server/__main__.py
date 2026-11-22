# -*- coding: utf-8 -*- {{{
# vim: set fenc=utf-8 ft=python sw=4 ts=4 sts=4 et:
#
# Copyright 2020, Battelle Memorial Institute.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This material was prepared as an account of work sponsored by an agency of
# the United States Government. Neither the United States Government nor the
# United States Department of Energy, nor Battelle, nor any of their
# employees, nor any jurisdiction or organization that has cooperated in the
# development of these materials, makes any warranty, express or
# implied, or assumes any legal liability or responsibility for the accuracy,
# completeness, or usefulness or any information, apparatus, product,
# software, or process disclosed, or represents that its use would not infringe
# privately owned rights. Reference herein to any specific commercial product,
# process, or service by trade name, trademark, manufacturer, or otherwise
# does not necessarily constitute or imply its endorsement, recommendation, or
# favoring by the United States Government or any agency thereof, or
# Battelle Memorial Institute. The views and opinions of authors expressed
# herein do not necessarily state or reflect those of the
# United States Government or any agency thereof.
#
# PACIFIC NORTHWEST NATIONAL LABORATORY operated by
# BATTELLE for the UNITED STATES DEPARTMENT OF ENERGY
# under Contract DE-AC05-76RL01830
# }}}
"""
The main entry point to the VOLTTRON server (the ``volttron`` command and ``python -m volttron.server``).

Logging is configured once, by ``run_server``, from the parsed options with the config file included. Until then
the records logged while the server's modules import are held in a bounded buffer and replayed at the configured
levels (volttron-core#362). This used to be a hand-written scan of ``sys.argv`` that recognised only ``-l PATH``
and ``-v``, so every other logging setting was ignored.
"""

import os
import sys

from volttron.server.logs import early_log_buffer, install_early_log_buffer, log_to_console, replay_early_logs


def main():
    install_early_log_buffer()

    if os.environ.get("VOLTTRON_HOME") is None:
        os.environ["VOLTTRON_HOME"] = os.path.expanduser("~/.volttron")
    # Create the volttron home if it doesn't exist.
    os.makedirs(os.path.join(os.environ["VOLTTRON_HOME"]), exist_ok=True)

    # Append PYTHONPATH variables to the system environment
    python_path = os.environ.get("PYTHONPATH")
    if python_path:
        for pth in python_path.split(":"):
            if pth not in sys.path:
                sys.path.insert(0, pth)

    try:
        from volttron.server.run_server import _main
        return _main()
    finally:
        if early_log_buffer() is not None:
            # The server stopped before configuring logging (an error, --help, --version): show what it logged.
            log_to_console()
            replay_early_logs()


if __name__ == "__main__":
    sys.exit(main())
