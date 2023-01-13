from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from pprint import pprint
from shutil import copy
from time import sleep
from typing import Any, Callable, Dict, Iterable, List, Optional

import yaml


@dataclass
class ConfigStoreEntry:
    name: str
    file: str
    type: str


@dataclass
class ServiceConfig:
    service: str
    enabled: bool
    libraries: Optional[List[str]] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def build(service: str, service_config: Dict) -> ServiceConfig:
        sc = ServiceConfig(service=service, **service_config)
        return sc


@dataclass
class AgentConfig:
    identity: str
    source: str
    libraries: Optional[List[str]] = field(default_factory=list)
    config: Optional[str | Dict] = None
    tag: Optional[str] = None
    config_store: Dict[str:ConfigStoreEntry] = field(default_factory=dict)

    def __post_init__(self):
        for name in self.config_store.keys():
            self.config_store[name] = ConfigStoreEntry(name, self.config_store[name]['file'],
                                                       self.config_store[name].get('type', ""))

    @staticmethod
    def build(identity: str, data: Dict) -> AgentConfig:
        ac = AgentConfig(identity=identity, **data)
        return ac


@dataclass
class PlatformConfig:
    vip_address: str
    instance_name: str

    verbosity: Optional[str] = "-vv"
    services: List[AgentConfig] = field(default_factory=list)
    agents: List[AgentConfig] = field(default_factory=list)

    @staticmethod
    def build(file: str) -> PlatformConfig:
        file = Path(file)
        if not file.exists():
            raise ValueError("Invalid file specified for PlatformConfig.build")

        contents = yaml.safe_load(file.open().read())
        pprint(contents)

        def normailze_dashes(data: Dict) -> Dict:
            new_dict = {}
            for k, v in data.items():
                new_k = k.replace('-', '_')
                new_dict[new_k] = v
            return new_dict

        contents['config'] = normailze_dashes(data=contents.get('config', {}))

        vip_address = contents['config'].get('vip_address', 'tcp://127.0.0.1:22916')
        instance_name = contents['config'].get('instance_name', os.environ['HOSTNAME'])

        pc = PlatformConfig(vip_address=vip_address, instance_name=instance_name)

        for identity, service_config in contents.get("services", {}).items():
            print(service_config)
            pc.services.append(ServiceConfig.build(identity, service_config))

        for identity, agent_config in contents.get("agents", {}).items():
            print(identity)
            pc.agents.append(AgentConfig.build(identity, agent_config))

        pprint(pc.__dict__)

        return pc


class VolttronThread(threading.Thread):
    
    def run(self):
        platform = subprocess.Popen(["volttron", "-v"],
                                    text=True,
                                    stderr=subprocess.STDOUT,
                                    stdout=subprocess.PIPE)

        while platform.poll() is None:
            line = platform.stdout.readline()
            sys.stdout.write(line)
            time.sleep(0.1)
    


if __name__ == "__main__":
    

    platform_config_file = os.environ.get("PLATFORM_CONFIG")
    reinit_platform = os.environ.get("REINITIALIZE")
    volttron_version = os.environ.get("VOLTTRON_VERSION")
    pip_cache_dir = os.environ.get("PIP_CACHE_DIR")
    volttron_home = os.environ.get("VOLTTRON_HOME")
    
    env_dir = os.environ.get("VOLTTRON_VENV")
    if not env_dir:
        raise ValueError("Invalid $VOLTTRON_VENV directory specified")
    
    
    def get_path_from_home(path: str):
        """Return a subpath from VOLTTRON_HOME"""
        return f"{volttron_home}/{path}"
    
    
    def exec(command: List[str]):
        """Execute a command using Popen and write out stdout and stderr to sys.stdout"""
        
        process = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while process.poll() is None:
            line = process.stdout.readline()
            sys.stdout.write(line)
            time.sleep(0.1)
        if process.returncode != 0:
            sys.exit(process.returncode)
    
    # Only create a new virtual env if we need it.
    if not Path(env_dir).joinpath("bin/python").exists():
        sys.stdout.write("Building virtual environment\n")
        cmd = ["python", "-m", "venv", env_dir]
        exec(cmd)
    
    # Make sure our executable is the one in the virtual environment.
    sys.executable = Path(env_dir).joinpath("bin/python")
    
    
    # Determine if we need to install volttron into the container.
    initialize_volttron = get_path_from_home("initialize_volttron")
    
    if not Path(initialize_volttron).exists():
        sys.stdout.write("Installing volttron\n")
        cmd = ["pip", "install", "volttron"]    
        exec(cmd)
        Path(initialize_volttron).write_text("Initialized")
    # process = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE)
    # while process.poll() is None:
    #     line = process.stdout.readline()
    #     sys.stdout.write(line)
    #     time.sleep(0.1)
    
    platform = VolttronThread(daemon=True)
    platform.start()
    
    while True:
        continue_loop = True
        try:
            stdout = subprocess.check_output(["vctl",  "peerlist"], text=True)
            for line in stdout.split():
                print(line)
                if "platform.control" in line:
                    continue_loop = False
                    break
            if not continue_loop:
                break                
        except subprocess.CalledProcessError:
            time.sleep(2)
            
            
    if platform_config_file:

        if not Path(platform_config_file).exists():
            raise ValueError(
                f"PLATFORM_CONFIG file not found {platform_config_file} did you mount properly.")

        initialized_file = Path(get_path_from_home('initialized'))
        if initialized_file.exists() and not reinit_platform:
            sys.exit(0)

        platform_config = PlatformConfig.build(platform_config_file)

        libs_needed = set()
        for s in platform_config.services:
            libs_needed.update(s.libraries)

        for a in platform_config.agents:
            libs_needed.update(s.libraries)

        if libs_needed:
            sys.stdout.write("Installing Libraries\n")
            sys.stdout.write("\n".join(libs_needed))
            cmd = ["pip", "install"]
            cmd.extend(libs_needed)            
            exec(cmd)
            

        if platform_config.services:
            service_config_path = Path(f"{os.environ['VOLTTRON_HOME']}/service_config.yml")
            os.makedirs(service_config_path.parent, exist_ok=True)
            service_dict = {}
            for s in platform_config.services:
                service_dict[s.service] = {}
                service_dict[s.service]['kwargs'] = s.kwargs
                service_dict[s.service]['enabled'] = s.enabled

            yaml.safe_dump(service_dict, service_config_path.open('wt'))

        
        if platform_config.agents:

            print("Installing agents.")
            
            for agent in platform_config.agents:
                sys.stdout.write(f"Installing agent {agent.identity}\n")
                config_pth = ""
                if isinstance(agent.config, str):
                    config_pth = Path(f"/config/{agent.config}")

                install_cmd = [
                    "vctl", "install", "--vip-identity", agent.identity, "--force",
                    "--enable", "--start"
                ]

                if not isinstance(config_pth, str) and config_pth.exists():
                    install_cmd.extend(["--agent-config", str(config_pth)])

                install_cmd.append(agent.source)
                
                subprocess.check_call(install_cmd)
                #exec(install_cmd)

                if agent.config_store:
                    for name, entry in agent.config_store.items():
                        file = Path(f"/config/{entry.file}")
                        if not file.exists():
                            raise ValueError(
                                f"Missing agent config_store file for {agent.identity} {file}")
                        config_store_cmd = [
                            "vctl", "config", "store", agent.identity, name,
                            str(file)
                        ]
                        if entry.type:
                            config_store_cmd.append(entry.type)
                            
                        subprocess.check_call(config_store_cmd)

            initialized_file.open("wt").write("Woot I have been initialized!")
    
    # Keep running until someone shuts it down.
    platform.join()