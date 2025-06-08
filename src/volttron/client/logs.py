import inspect
import logging
import warnings
from logging import Logger
import sys
import os

import volttron.utils.jsonapi as jsonapi


def get_default_client_log_config(level=logging.DEBUG) -> dict:
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "simple": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": level,
                "formatter": "simple",
                "stream": "ext://sys.stdout"
            },
            "file": {
                "class": "logging.FileHandler",
                "level": "INFO",
                "formatter": "simple",
                "filename": "myapp.log",
                "mode": "a"
            }
        },
        "loggers": {
            "volttron.client": {
                "level": level
            }
        },
        "root": {
            "level": level,
            "handlers": ["console"]
        }
    }


class JsonFormatter(logging.Formatter):

    def format(self, record):
        dct = record.__dict__.copy()
        dct["msg"] = record.getMessage()
        dct.pop("args")
        exc_info = dct.pop("exc_info", None)
        if exc_info:
            dct["exc_text"] = "".join(traceback.format_exception(*exc_info))
        return jsonapi.dumps(dct)


class AgentFormatter(logging.Formatter):

    def __init__(self, fmt=None, datefmt=None):
        if fmt is None:
            fmt = "%(asctime)s %(composite_name)s %(levelname)s: %(message)s"
        super(AgentFormatter, self).__init__(fmt=fmt, datefmt=datefmt)

    def composite_name(self, record):
        if record.name == "agents.log":
            cname = "(%(processName)s %(process)d) %(remote_name)s"
        elif record.name.startswith("agents.std"):
            cname = "(%(processName)s %(process)d) <{}>".format(record.name.split(".", 2)[1])
        else:
            cname = "() %(name)s"
        return cname % record.__dict__

    def format(self, record):
        if "composite_name" not in record.__dict__:
            record.__dict__["composite_name"] = self.composite_name(record)
        return super(AgentFormatter, self).format(record)


def setup_logging(level=logging.DEBUG, console=False):
    from volttron.utils.commands import isapipe

    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()

        if isapipe(sys.stderr) and "_LAUNCHED_BY_PLATFORM" in os.environ:
            handler.setFormatter(JsonFormatter())
        elif console:
            # Below format is more readable for console
            handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        else:
            fmt = "%(asctime)s %(name)s %(levelname)s: %(message)s"
            handler.setFormatter(logging.Formatter(fmt))
        if level != logging.DEBUG:
            # import it here so that when urllib3 imports the requests package, ssl would already got
            # monkey patched by gevent.
            # and this warning is needed only when log level is not debug
            from urllib3.exceptions import InsecureRequestWarning

            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        root.addHandler(handler)
    root.setLevel(level)

    logging.getLogger("volttron.messagebus").setLevel("INFO")
    logging.getLogger("volttron.server").setLevel("WARN")
