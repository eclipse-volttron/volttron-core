import argparse


def add_rpc_authorization(opts: argparse.Namespace):
    """
    Validates user input and calls the auth service method to add authorization to a method.

    :param opts: Contains command line pattern and connection
    :return: None
    """
    conn = opts.connection
    assert conn, "Connection not available."

    identity_list = [value.split(".") for value in opts.identity_and_method]

    print(identity_list)

    # for identity, method in opts.identity_and_method:

    # opts.identity_and_method[0]

    # agent_id = ".".join(opts.pattern[0].split(".")[:-1])
    # agent_method = opts.pattern[0].split(".")[-1]
    # if len(opts.pattern) < 2:
    #     _log.error("Missing authorizations for method. "
    #                "Should be in the format agent_id.method "
    #                "authorized_capability1 authorized_capability2 ...")
    #     return
    # added_auths = [x for x in opts.pattern[1:]]
    # try:
    #     conn.server.vip.rpc.call(AUTH, "add_rpc_authorizations", agent_id, agent_method,
    #                              added_auths).get(timeout=4)
    # except TimeoutError:
    #     _log.error(f"Adding RPC authorizations {added_auths} for {agent_id}'s "
    #                f"method {agent_method} timed out")
    # except Exception as e:
    #     _log.error(f"{e}) \nCommand format should be agent_id.method "
    #                f"authorized_capability1 authorized_capability2 ...")
    # return


def remove_agent_rpc_authorization(opts):
    """
    Removes authorizations to method in auth entry in auth file.

    :param opts: Contains command line pattern and connection
    :return: None
    """
    conn = opts.connection
    agent_id = ".".join(opts.pattern[0].split(".")[:-1])
    agent_method = opts.pattern[0].split(".")[-1]
    if len(opts.pattern) < 2:
        _log.error("Missing authorizations for method. "
                   "Should be in the format agent_id.method "
                   "authorized_capability1 authorized_capability2 ...")
        return
    removed_auths = [x for x in opts.pattern[1:]]
    try:
        conn.server.vip.rpc.call(
            AUTH,
            "delete_rpc_authorizations",
            agent_id,
            agent_method,
            removed_auths,
        ).get(timeout=4)
    except TimeoutError:
        _log.error(f"Adding RPC authorizations {removed_auths} for {agent_id}'s "
                   f"method {agent_method} timed out")
    except Exception as e:
        _log.error(f"{e}) \nCommand format should be agent_id.method "
                   f"authorized_capability1 authorized_capability2 ...")
    return


def add_authz_parser(add_parser_fn, filterable):
    """Create and populate an argparse parser for the authz command.

    First create the top level parser for authz.  Then create a subparser for
    the rpc subcommand.  Finally adds seperate arguments to the rpc subparser
    for add, remove and list commands.

    The same method as above is how the pubsub subcommand will be added.

    :param add_parser_fn: A callback that will create a new parser based upon parameters passed
    :type add_parser_fn: Callable
    :param filterable: A filter function for filtering the results of the command
    :type filterable: Callable
    """

    # TODO: Verify that the filterable makes sense for the authz command.

    authz_commands = add_parser_fn("authz",
                                   help="Manage authorization for rpc methods and pubsub topics")

    rpc_parser = authz_commands.add_subparsers(title="rpc", metavar="", dest="store_commands")

    add_authz_method = add_parser_fn("add",
                                     subparser=rpc_parser,
                                     help="Add rpc method authorization")
    add_authz_method.add_argument(
        "identity_and_method",
        nargs="*",
        help="Add rpc authorization to an agent.  Format is 'identity.method_name'")
    add_authz_method.set_defaults(func=add_rpc_authorization)

    remove_authz_method = add_parser_fn(
        "remove",
        subparser=rpc_parser,
        help="Remove rpc method authorization, format is identity.method_name")
    remove_authz_method.add_argument(
        "identity_and_method",
        nargs="*",
        help="Remove rpc authorization to an agent.  Format is 'identity.method_name'")
    remove_authz_method.set_defaults(func=remove_agent_rpc_authorization)

    list_authz_method = add_parser_fn("list",
                                      subparser=rpc_parser,
                                      help="List authorized rpc methods.")
    #list_authz_method.set_defaults(func=print_rpc_authorizations)
