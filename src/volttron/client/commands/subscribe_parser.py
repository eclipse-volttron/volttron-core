

import argparse
import sys
import os

import gevent

from volttron.client.known_identities import AUTH


def on_message(peer, sender, bus, topic, headers, message):
    print('*'*80)
    print("Received:")
    print(f"\tpeer={peer},sender={sender},topic={topic})")
    print(f"\theaders={headers}")
    print(f"\tmessage={message}")
    print('-'*80)


def subscribe_to_bus(opts):

    if opts.identity_stage:
        print(f"Subscribing to {opts.topic}")
        from pathlib import Path
        from volttron.utils import ClientContext as cc
        from volttron.client.vip.agent import Agent as BaseAgent
        from volttron.types.auth import Credentials, VolttronCredentials
        from volttron.types.agent_context import AgentOptions
        from volttron.utils import jsonapi
        credentials_path = Path(
            cc.get_volttron_home()) / "credentials_store" / f"{opts.identity_stage}.json"
        if not credentials_path.exists():
            raise ValueError(f"Control connection credentials not found at {credentials_path}")

        credjson = jsonapi.load(credentials_path.open("r"))

        credentials = VolttronCredentials(**credjson)
        options = AgentOptions(heartbeat_autostart=False,
                                volttron_home=cc.get_volttron_home(),
                                enable_store=False)
        agent = BaseAgent(credentials=credentials, options=options, address=opts.address)
        event = gevent.event.Event()
        greenlet = gevent.spawn(agent.core.run, event)
        event.wait()

        agent.vip.pubsub.subscribe('pubsub', prefix=opts.topic, callback=on_message, all_platforms=opts.all_platforms).get(1)

        try:
            greenlet.join()
        except KeyboardInterrupt:
            #print("Complete")
            pass
        finally:
            print("Stopping Subscriptions")
            agent.core.stop()
        
        sys.exit()
               

    conn = opts.connection
    count = 0
    root_identity = f"subscriber"
    peers = sorted(conn.call("peerlist"))

    subscription_identity = f"subscriber{count}"

    while True:
        if subscription_identity in peers:
            count += 1
            subscription_identity = f"subscriber{count}"
            continue
        break
    
    # print(opts)
    # print(sys.executable)
    # print(sys.argv)
    # print(f"Creating credentials for {subscription_identity}")
    # We need to create new credentials or have one that is created already for us.
    value = conn.server.vip.rpc.call(AUTH, "create_credentials", identity=subscription_identity).get(timeout=4)
    args = sys.argv.copy()
    args.extend(['--identity-stage', subscription_identity])
    
    # This process will now execute in the currently executing process.  It is not like
    # subprocess in that it will not exit until the process ends.
    os.execvp(args[0], args=args)


    
    #opts.connection.server.vip.pubsub.publish("pubsub", topic=opts.topic, message=opts.data).get()

def add_subscribe_parser(add_parser_fn):

    subscriber = add_parser_fn("subscribe", help="Allow a subscription to listen to the bus and print out responses.")
    
    #publisher_subparser = publisher.add_subparsers(title="publish options")
    
    subscriber.add_argument("topic", help="Topic to publish to")
    subscriber.add_argument("--all-platforms", action="store_true",
                            help="Subscribe to all platforms for this topic/prefix")
    subscriber.add_argument("--identity-stage", default=None, help=argparse.SUPPRESS)
    subscriber.set_defaults(func=subscribe_to_bus)