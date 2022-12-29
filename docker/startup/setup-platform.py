from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from pprint import pprint
from shutil import copy
from time import sleep
from typing import Any, Dict, List, Optional

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
    config_store: Dict[str: ConfigStoreEntry] = field(default_factory=dict)
    
    @staticmethod
    def build(identity:str, data: Dict) -> AgentConfig:
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
    
        
        
        
    
    
    
# from volttron.platform import set_home, certs
# from volttron.platform.agent.known_identities import PLATFORM_WEB
# from volttron.utils import get_hostname
# from slogger import get_logger

# slogger = get_logger("setup-platform", "setup-platform")

# # The environment variables must be set or we have big issues
# VOLTTRON_ROOT = os.environ["VOLTTRON_ROOT"]
# VOLTTRON_HOME = os.environ["VOLTTRON_HOME"]
# RMQ_HOME = os.environ["RMQ_HOME"]
# VOLTTRON_CMD = "volttron"
# VOLTTRON_CTL_CMD = "volttron-ctl"
# VOLTTRON_CFG_CMD = "vcfg"
# INSTALL_PATH = "{}/scripts/install-agent.py".format(VOLTTRON_ROOT)
# KEYSTORES = os.path.join(VOLTTRON_HOME, "keystores")
# AGENT_START_TIME = "10"


# if not VOLTTRON_HOME:
#     VOLTTRON_HOME = "/home/volttron/.volttron"


def get_platform_config_path():
    platform_config = None
    if "PLATFORM_CONFIG" in os.environ and os.environ["PLATFORM_CONFIG"]:
        platform_config = os.environ["PLATFORM_CONFIG"]
    elif os.path.isfile("/platform_config.yml"):
        platform_config = "/platform_config.yml"
    slogger.info(f"Platform_config: {platform_config}")

    # Stop processing if platform config hasn't been specified
    if platform_config is None:
        sys.stderr.write("No platform configuration specified.")
        slogger.debug("No platform configuration specified.")
        sys.exit(0)

    return platform_config


def get_platform_configurations(platform_config_path):
    with open(platform_config_path) as cin:
        config = yaml.safe_load(cin)
        agents = config["agents"]
        platform_cfg = config["config"]

    print("Platform instance name set to: {}".format(platform_cfg.get("instance-name")))

    return config, agents, platform_cfg


def _install_required_deps():
    # install required volttron dependencies, wheel and pyzmq, because they are not required in setup.py
    # opt_reqs is a list of tuples, in which the tuple consists pf a pinned dependency and a list of zero or more options
    # example: [('wheel==0.30', []), ('pyzmq==22.2.1', ['--zmq=bundled'])]
    from requirements import option_requirements as opt_reqs

    for req in opt_reqs:
        package, options = req
        install_cmd = ["pip3", "install", "--no-deps"]
        # TODO: see if options can be used as part of installation
        # if options:
        #     for opt in options:
        #         install_cmd.extend([f"--install-option=\"{opt}\""])
        # install_cmd.append(f'--install-option="{opt}"')
        install_cmd.append(package)
        subprocess.check_call(install_cmd)


def _install_web_deps(bind_web_address):
    print(f"Platform bind web address set to: {bind_web_address}")
    from requirements import extras_require as extras

    web_plt_pack = extras.get("web", None)
    install_cmd = ["pip3", "install"]
    install_cmd.extend(web_plt_pack)
    if install_cmd is not None:
        print(f"Installing packages for web platform: {web_plt_pack}")
        subprocess.check_call(install_cmd)


def _create_platform_config_file(platform_cfg, cfg_path):
    if not os.path.exists(cfg_path) and len(platform_cfg) > 0:
        with open(os.path.join(cfg_path), "w") as fout:
            fout.write("[volttron]\n")
            for key, value in platform_cfg.items():
                fout.write("{}={}\n".format(key.strip(), value.strip()))


def _create_certs(cfg_path, platform_cfg):
    print("Creating CA Certificate...")
    crts = certs.Certs()
    data = {
        "C": "US",
        "ST": "WA",
        "L": "Richmond",
        "O": "PNNL",
        "OU": "Volttron",
        "CN": f"{platform_cfg.get('instance-name')}-root-ca",
    }
    crts.create_root_ca(overwrite=False, **data)
    copy(crts.cert_file(crts.root_ca_name), crts.cert_file(crts.trusted_ca_name))

    print("Creating new web server certificate.")
    print(
        "Creating and signing new certificate using the newly created CA certificate."
    )
    name = f"{platform_cfg.get('instance-name')}-{PLATFORM_WEB}"
    crts.create_signed_cert_files(
        name=name + "-server",
        cert_type="server",
        ca_name=crts.root_ca_name,
        fqdn=get_hostname(),
    )

    master_web_cert = os.path.join(
        VOLTTRON_HOME, "certificates/certs/", name + "-server.crt"
    )
    master_web_key = os.path.join(
        VOLTTRON_HOME, "certificates/private/", name + "-server.pem"
    )
    print("Writing ssl cert and key paths to config.")
    with open(os.path.join(cfg_path), "a") as fout:
        fout.write(f"web-ssl-cert = {master_web_cert}\n")
        fout.write(f"web-ssl-key = {master_web_key}\n")


def _create_rmq_config(platform_cfg, config):
    # validation checks
    if not config.get("rabbitmq-config"):
        sys.stderr.write(
            "Invalid rabbit-config entry in platform configuration file.\n"
        )
        sys.exit(1)

    rabbitcfg_file = os.path.expandvars(
        os.path.expanduser(config.get("rabbitmq-config"))
    )
    if not os.path.isfile(rabbitcfg_file):
        sys.stderr.write("Invalid rabbit-config entry {} \n".format(rabbitcfg_file))
        sys.exit(1)
    with open("/etc/hostname") as hostfile:
        hostname = hostfile.read().strip()
    if not hostname:
        sys.stderr.write(
            "Invalid hostname set, please set it in the docker-compose or in the container."
        )
        sys.exit(1)

    # Now we can configure the rabbit/rmq configuration
    with open(rabbitcfg_file) as cin:
        rabbit_config = yaml.safe_load(cin)

    # set host
    rabbit_config["host"] = hostname

    # set use-existing-certs
    certs_test_path = os.path.join(
        VOLTTRON_HOME,
        "certificates/certs/{}-trusted-cas.crt".format(
            platform_cfg.get("instance-name")
        ),
    )
    if os.path.isfile(certs_test_path):
        rabbit_config["use-existing-certs"] = True

    # Set rmq_home
    print(f"Setting rmq-home to {RMQ_HOME}")
    rabbit_config["rmq-home"] = RMQ_HOME

    # Create rmq config YAML file
    rabbitfilename = os.path.join(VOLTTRON_HOME, "rabbitmq_config.yml")
    print("Creating rabbitmq conifg file at {}".format(rabbitfilename))
    print("dumpfile is :{}".format(rabbit_config))
    with open(rabbitfilename, "w") as outfile:
        yaml.dump(rabbit_config, outfile, default_flow_style=False)
    assert os.path.isfile(rabbitfilename)


def _setup_rmq(platform_cfg):
    now_dir = os.getcwd()
    os.chdir(VOLTTRON_ROOT)
    # we must import the function here because it requires pyzmq, which is not installed during the image build but in configure_platform, which is called before this function
    from volttron.platform.instance_setup import setup_rabbitmq_volttron

    setup_rabbitmq_volttron(
        "single", True, instance_name=platform_cfg.get("instance-name")
    )
    os.chdir(now_dir)


def configure_platform(platform_cfg, config):
    # install required dependencies (this is temporary due to setup.py of volttron)
    _install_required_deps()

    # install web dependencies if web-enabled
    bind_web_address = platform_cfg.get("bind-web-address", None)
    if bind_web_address is not None:
        print(f"Platform bind web address set to: {bind_web_address}")
        _install_web_deps(bind_web_address)

    # Create the main volttron config file
    if not os.path.isdir(VOLTTRON_HOME):
        os.makedirs(VOLTTRON_HOME)

    cfg_path = os.path.join(VOLTTRON_HOME, "config")

    # create platform config file
    _create_platform_config_file(platform_cfg, cfg_path)

    # create the certs
    _create_certs(cfg_path, platform_cfg)

    # setup rmq if necessary
    if platform_cfg.get("message-bus") == "rmq":
        _create_rmq_config(platform_cfg, config)
        _setup_rmq(platform_cfg)


def install_agents(agents):
    need_to_install = {}

    sys.stdout.write("Available agents that are needing to be setup/installed")
    print(f"{agents.keys()}")

    # TODO Fix so that the agents identities are consulted.
    for identity, specs in agents.items():
        path_to_keystore = os.path.join(KEYSTORES, identity)
        if not os.path.exists(path_to_keystore):
            need_to_install[identity] = specs

    # if we need to do installs then we haven't setup this at all.
    if need_to_install:
        # Start volttron first because we can't install anything without it
        proc = subprocess.Popen([VOLTTRON_CMD, "-vv"])
        assert proc is not None
        sleep(20)

        envcpy = os.environ.copy()
        failed_install = []
        for identity, spec in need_to_install.items():
            slogger.info("Processing identity: {}".format(identity))
            sys.stdout.write("Processing identity: {}\n".format(identity))
            if "source" not in spec:
                slogger.info(f"Invalid source for identity: {identity}")
                sys.stderr.write("Invalid source for identity: {}\n".format(identity))
                continue

            # get the source code of the agent
            agent_source = os.path.expandvars(os.path.expanduser(spec["source"]))
            if not os.path.exists(agent_source):
                slogger.info(
                    f"Invalid agent source {agent_source} for identity {identity}"
                )
                sys.stderr.write(
                    "Invalid agent source ({}) for agent id identity: {}\n".format(
                        agent_source, identity
                    )
                )
                continue

            # get agent configuration
            agent_cfg = None
            if "config" in spec and spec["config"]:
                agent_cfg = os.path.abspath(
                    os.path.expandvars(os.path.expanduser(spec["config"]))
                )
                if not os.path.exists(agent_cfg):
                    slogger.info(f"Invalid config {agent_cfg} for identity {identity}")
                    sys.stderr.write(
                        "Invalid config ({}) for agent id identity: {}\n".format(
                            agent_cfg, identity
                        )
                    )
                    continue

            # grab the priority from the system config file
            priority = spec.get("priority", "50")
            tag = spec.get("tag", "all_agents")

            install_cmd = ["python3", INSTALL_PATH]
            install_cmd.extend(["--agent-source", agent_source])
            install_cmd.extend(["--vip-identity", identity])
            install_cmd.extend(["--start", "--priority", priority])
            install_cmd.extend(["--agent-start-time", AGENT_START_TIME])
            install_cmd.append("--force")
            install_cmd.extend(["--tag", tag])

            if agent_cfg:
                install_cmd.extend(["--config", agent_cfg])

            # This allows install agent to ignore the fact that we aren't running
            # form a virtual environment.
            envcpy["IGNORE_ENV_CHECK"] = "1"
            try:
                subprocess.check_call(install_cmd, env=envcpy)
            except subprocess.CalledProcessError as e:
                # sometimes, the install command returns an Error saying that volttron couldn't install the agent, when in fact the agent was successfully installed
                # this is most likely a bug in Volttron. For now, we are ignoring that error so that the setup of the Volttron platform does not fail and to allow Docker to start the container
                sys.stderr.write(f"IGNORING ERROR: {e}")
                slogger.debug(f"IGNORING ERROR: {e}")
                failed_install.append(identity)
                continue

            if "config_store" in spec:
                sys.stdout.write("Processing config_store entries")
                for key, entry in spec["config_store"].items():
                    if "file" not in entry or not entry["file"]:
                        slogger.info(
                            f"Invalid config store entry; file must be specified for {key}"
                        )
                        sys.stderr.write(
                            "Invalid config store entry file must be specified for {}".format(
                                key
                            )
                        )
                        continue
                    entry_file = os.path.expandvars(os.path.expanduser(entry["file"]))

                    if not os.path.exists(entry_file):
                        slogger.info(
                            f"Invalid config store file not exist: {entry_file}"
                        )
                        sys.stderr.write(
                            "Invalid config store file does not exist {}".format(
                                entry_file
                            )
                        )
                        continue

                    entry_cmd = [
                        VOLTTRON_CTL_CMD,
                        "config",
                        "store",
                        identity,
                        key,
                        entry_file,
                    ]
                    if "type" in entry:
                        entry_cmd.append(entry["type"])

                    subprocess.check_call(entry_cmd)
        slogger.info(f"Agents that failed to install {failed_install}")


def final_platform_configurations():
    # allows platform to automatically accept all incoming auth requests
    auth_add = ["vctl", "auth", "add", "--credentials", "/.*/"]
    slogger.info(f"Adding * creds to auth. {auth_add}")
    subprocess.call(auth_add)

    sys.stdout.write("\n**************************************************\n")
    sys.stdout.write("SHUTTING DOWN FROM SETUP-PLATFORM.PY\n")
    slogger.info("SHUTTING DOWN FROM SETUP-PLATFORM.PY")
    sys.stdout.write("**************************************************\n")
    subprocess.call(["vctl", "shutdown", "--platform"])

    sleep(5)
    sys.exit(0)


if __name__ == "__main__":
    
    platform_config_file = os.environ.get("PLATFORM_CONFIG")
    reinit_platform = os.environ.get("REINITIALIZE")
    
    def get_path_from_home(path: str):
        return f"{os.environ['VOLTTRON_HOME']}/{path}"
    
    if platform_config_file:
        
        if not Path(platform_config_file).exists():
            raise ValueError(f"PLATFORM_CONFIG file not found {platform_config_file} did you mount properly.")
        
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
            cmd = ["pip", "install"]
            cmd.extend(libs_needed)
            print("Installing Libraries")
            print("\n".join(libs_needed))
            process = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE)
            while process.poll() is None:
                line = process.stdout.readline()
                
                #if line.startswith("Collecting") or line.startswith("Install"):
                sys.stdout.write(line)
                time.sleep(0.1)
            # completed = subprocess.run(cmd, capture_output=True)
            # completed.check_returncode()
        
        if platform_config.services:
            service_config_path = Path(f"{os.environ['VOLTTRON_HOME']}/service_config.yml")
            os.makedirs(service_config_path.parent, exist_ok=True)
            service_dict = {}
            for s in platform_config.services:
                service_dict[s.service] = {}
                service_dict[s.service]['kwargs'] = s.kwargs
                service_dict[s.service]['enabled'] = s.enabled
            
            yaml.safe_dump(service_dict, service_config_path.open('wt'))
            
        pid_pth = Path(get_path_from_home("VOLTTRON_PID"))
        if pid_pth.exists():
            os.remove(pid_pth)
            
        if platform_config.agents:       
            print("Starting volttron")
            process = subprocess.Popen(["volttron", "-vv"], text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            time_slept = 0
            while process.poll() is None:
                if time_slept > 5:
                    break
                #line = process.stdout.readline()
                line_err = process.stderr.readline()
                #sys.stdout.write(line)
                sys.stdout.write(line_err)
                time_slept += 0.1
                time.sleep(0.1)
                
            time.sleep(10)
                
            for agent in platform_config.agents:
                print(f"Installing agent {agent.identity}")
                config_pth = ""
                if isinstance(agent.config, str):
                    config_pth = Path(f"/config/{agent.config}")
                
                install_cmd = ["vctl",
                               "-vv",
                               "install", 
                               "--vip-identity", agent.identity,
                               "--force",
                               "--enable",
                               "--start"]
                
                if config_pth:
                    install_cmd.extend(["--agent-config", str(config_pth)])
                    
                install_cmd.append(agent.source)
                
                success = subprocess.Popen(install_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                while success.poll() is None:
                    line = success.stdout.readline()
                    sys.stdout.write(line)
                    time.sleep(0.1)
            
            print("Shutting down platform")
            process = subprocess.Popen(["vctl", "shutdown", "--platform"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            while process.poll():
                line = success.stdout.readline()
                sys.stdout.write(line)        
                time.sleep(0.1)

            initialized_file.open("wt").write("Woot I have been initialized!")
            
            
            
        

            
        
    # set_home(VOLTTRON_HOME)
    # config_tmp, agents_tmp, platform_cfg_tmp = get_platform_configurations(
    #     get_platform_config_path()
    # )
    
    # configure_platform(platform_cfg_tmp, config_tmp)
    # install_agents(agents_tmp)
    # final_platform_configurations()