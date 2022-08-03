import gevent


class ServiceInterface:

    def spawn_in_greenlet(self):
        return gevent.spawn(self.core.run)
