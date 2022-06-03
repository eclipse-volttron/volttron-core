import threading


class Monitor(threading.Thread):
    """Monitor thread to log connections."""

    def __init__(self, sock):
        super(Monitor, self).__init__()
        self.daemon = True
        self.sock = sock

    def run(self):
        events = {
            value: name[6:]
            for name, value in vars(zmq).items()
            if name.startswith("EVENT_") and name != "EVENT_ALL"
        }
        log = logging.getLogger("vip.monitor")
        if log.level == logging.NOTSET:
            log.setLevel(logging.INFO)
        sock = self.sock
        while True:
            event, endpoint = sock.recv_multipart()
            event_id, event_value = struct.unpack("=HI", event)
            event_name = events[event_id]
            log.info("%s %s %s", event_name, event_value, endpoint)
