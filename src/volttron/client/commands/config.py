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


def main():
    global verbose, prompt_vhome
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--vhome", help="Path to volttron home")
    parser.add_argument(
        "--instance-name",
        dest="instance_name",
        help="Name of this volttron instance",
    )

    group = parser.add_mutually_exclusive_group()

    agent_list = "\n\t" + "\n\t".join(sorted(available_agents.keys()))
    group.add_argument(
        "--list-agents",
        action="store_true",
        dest="list_agents",
        help="list configurable agents{}".format(agent_list),
    )

    group.add_argument("--agent", nargs="+", help="configure listed agents")
    group.add_argument(
        "--rabbitmq",
        nargs="+",
        help="Configure rabbitmq for single instance, "
        "federation, or shovel either based on "
        "configuration file in yml format or providing "
        "details when prompted. \nUsage: vcfg --rabbitmq "
        "single|federation|shovel [rabbitmq config "
        "file]",
    )
    group.add_argument(
        "--secure-agent-users",
        action="store_true",
        dest="secure_agent_users",
        help="Require that agents run with their own users (this requires running "
        "scripts/secure_user_permissions.sh as sudo)",
    )

    args = parser.parse_args()
    verbose = args.verbose
    # Protect against configuration of base logger when not the "main entry point"
    if verbose:
        setup_logging(logging.DEBUG, True)
    else:
        setup_logging(logging.INFO, True)

    prompt_vhome = True
    if args.vhome:
        set_home(args.vhome)
        prompt_vhome = False
    # if not args.rabbitmq or args.rabbitmq[0] in ["single"]:
    fail_if_instance_running()
    fail_if_not_in_src_root()
    atexit.register(_cleanup_on_exit)
    _load_config()
    if args.instance_name:
        _update_config_file(instance_name=args.instance_name)
    if args.list_agents:
        print("Agents available to configure:{}".format(agent_list))
    elif args.rabbitmq:
        if len(args.rabbitmq) > 2:
            print("vcfg --rabbitmq can at most accept 2 arguments")
            parser.print_help()
            sys.exit(1)
        elif args.rabbitmq[0] not in ["single", "federation", "shovel"]:
            print("Usage: vcf --rabbitmq single|federation|shovel "
                  "[optional path to rabbitmq config yml]")
            parser.print_help()
            sys.exit(1)
        elif len(args.rabbitmq) == 2 and not os.path.exists(args.rabbitmq[1]):
            print("Invalid rabbitmq configuration file path.")
            parser.print_help()
            sys.exit(1)
        else:
            process_rmq_inputs(args.rabbitmq, args.instance_name)
    elif args.secure_agent_users:
        config_opts["secure-agent-users"] = args.secure_agent_users
        _update_config_file()
    elif not args.agent:
        wizard()

    else:
        # Warn about unknown agents
        valid_agents = False
        for agent in args.agent:
            if agent not in available_agents:
                print('"{}" not configurable with this tool'.format(agent))
            else:
                valid_agents = True
        if valid_agents:
            confirm_volttron_home()

        # Configure agents
        for agent in args.agent:
            try:
                available_agents[agent]()
            except KeyError:
                pass
