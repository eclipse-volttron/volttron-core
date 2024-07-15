from dataclasses import dataclass

from volttron.server.aip import AIPplatform


@dataclass
class Env:
    volttron_home: str = "/tmp/tmp"


opt = Env()


def test_aip_agent_subpath():

    aip = AIPplatform(opt)
    install_dir = aip.install_dir
    path = aip.get_subpath('foo', "bar")
    assert f"{install_dir}/foo/bar" == path