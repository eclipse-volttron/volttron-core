

def publish_to_bus(opts):
    print(f"Publishing to {opts.topic} {opts.data}")
    opts.connection.server.vip.pubsub.publish("pubsub", topic=opts.topic, message=opts.data).get()

def add_publish_parser(add_parser_fn):

    publisher = add_parser_fn("publish", help="Allow a single shot publisher to the bus from the command line.")
    
    #publisher_subparser = publisher.add_subparsers(title="publish options")
    
    publisher.add_argument("topic", help="Topic to publish to")
    publisher.add_argument("data", help="Data to publish")
    # publisher_subparser.add_argument("--internal-only", action="store_true"
    #                                  help="Should it be published internally only?")

    publisher.set_defaults(func=publish_to_bus)