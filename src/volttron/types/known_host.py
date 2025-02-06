from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dataclass_wizard import JSONSerializable, JSONWizard

from volttron.types.blinker_events import volttron_home_set_evnt

PropertyValue = str | int | float


@dataclass
class _KnownHostProperties(JSONWizard):
    hosts: dict[str, dict] = field(default_factory=dict)

    def add_property(self, host: str, key: str, value: PropertyValue):
        if host not in self.hosts:
            self.hosts[host] = dict()
        self.hosts[host][key] = value

    def has_property(self, host: str, key: str) -> bool:
        return key in self.hosts[host]

    def get_property(self, host: str, key: str) -> PropertyValue:
        return self.hosts[host][key]

    def store(self, path: Path | str):
        if isinstance(path, str):
            path = Path(path)
        path.open("w").write(self.to_json(indent=2))

    def get_host_properties(self, host: Optional[str]) -> dict[str, PropertyValue]:
        if host is None:
            return self.hosts["@"]
        return self.hosts.get(host, dict())

    @staticmethod
    def load(path: Path) -> KnownHostProperties:
        if isinstance(path, str):
            path = Path(path)

        if path.exists():
            obj = _KnownHostProperties.from_json(path.open().read())
        else:
            obj = _KnownHostProperties()
        return obj


KnownHostProperties = None


@volttron_home_set_evnt.connect
def volttron_home(sender: Any):
    global KnownHostProperties
    volttron_home = os.environ.get("VOLTTRON_HOME")
    assert volttron_home, "Requires VOLTTRON_HOME to be set"
    KnownHostProperties = _KnownHostProperties.load(Path(volttron_home) / "known_hosts.json")


if __name__ == '__main__':
    import json

    old = json.loads("""{
    "@": "2YYmfjduH-D2SzPZO85dkubqv3aCJlJTfB_C514LXRA",
    "127.0.0.1:22916": "2YYmfjduH-D2SzPZO85dkubqv3aCJlJTfB_C514LXRA"
    }""")

    p = KnownHostProperties()
    p.add_property("@", "publickey", old["@"])
    p.add_property("@", "publickey", old["@"])
    p.add_property("127.0.0.1:22916", "publickey", old["127.0.0.1:22916"])

    print(p.to_json(indent=2))
    p.store("foo.json")

    b = KnownHostProperties.load("foo.json")

    print(b.to_json(indent=2))
