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
This is the main entry point to the VOLTTRON server. The first thing that
should happen is setting up of logging and verbosity for the server.  After
that we hand off to the run_server method, which will start the server process.
"""
import logging
import logging.config
import os
from pathlib import Path
import sys

import yaml

from volttron.server.logs import get_default_logging_config, log_to_file, configure_logging

file_to_log_to: str | None = None
total_count: int = 0
logging_config: Path | str | None = None

arg_iter = iter(sys.argv)
for arg in arg_iter:
    vcount = 0

    if arg.startswith("-v"):
        vcount = arg.count("v")
    elif arg == "--verbose":
        vcount = 1
    elif arg == "--log" or arg == "-l":
        file_to_log_to = next(arg_iter)

    elif arg == "--log-config" or arg == "-L":
        # Find the index of the log configuration so we can replace the
        # file with absolute path.
        try:
            index = sys.argv.index("--log-config")
        except ValueError:
            index = sys.argv.index("-L")

        # Get the logging config file and verify it's existence.
        logging_config = Path(sys.argv[index + 1])
        if not logging_config.exists():
            sys.stderr.write(f"Invalid --log-config file passed {logging_config}")
            sys.exit(10)

        # Finally set the logging parameter to the absolute path
        sys.argv[index + 1] = logging_config.absolute().as_posix()

    total_count += vcount

if os.environ.get("VOLTTRON_HOME") is None:
    os.environ["VOLTTRON_HOME"] = os.path.expanduser("~/.volttron")

# Create the volttron home if it doesn't exist.
os.makedirs(os.path.join(os.environ["VOLTTRON_HOME"]), exist_ok=True)

if logging_config and total_count > 0:
    sys.stderr.write("Cannot specify both --log-config and --verbose options\n"
                     "Update the logging config file to set the verbosity level")
    sys.exit(1)

if logging_config and file_to_log_to:
    sys.stderr.write("Cannot specify both --log and --log-config options\n"
                     "Update the logging config file to specify the log file")
    sys.exit(1)

# If the user has specified a logging configuration then allow them full access to all the
# responsibility of logging.
if logging_config:
    configure_logging(logging_config)

else:
    # The user wants to output all to a file so we can do that for them.
    if file_to_log_to:
        log_to_file(file_to_log_to, total_count, handler_class=logging.handlers.WatchedFileHandler)

    # Normal here just use the default stream handler setup.
    else:
        logging.config.dictConfig(get_default_logging_config(level=total_count))

from volttron.server.run_server import _main

# Append PYTHONPATH variables to the system environment
python_path = os.environ.get("PYTHONPATH")
if python_path:
    for pth in python_path.split(":"):
        if pth not in sys.path:
            sys.path.insert(0, pth)

_main()
