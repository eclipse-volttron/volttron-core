# Eclipse VOLTTRON™

Eclipse VOLTTRON (eclipse-volttron/volttron-core) is an open source platform for distributed sensing and control. The platform provides services for collecting and storing data from buildings and devices and provides an environment for developing applications which interact with that data.

[![Eclipse VOLTTRON™](https://img.shields.io/badge/Eclips%20VOLTTRON--red.svg)](https://volttron.readthedocs.io/en/latest/)
![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
[![Pytests](https://github.com/eclipse-volttron/volttron-core/actions/workflows/run-tests.yml/badge.svg)](https://github.com/eclipse-volttron/volttron-core/actions/workflows/run-tests.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron.svg)](https://pypi.org/project/volttron/)

## Prerequisites

- poetry >= 2.0.1
- python >= 3.10
- pip >= 24.0

  Note: Ubuntu 22.04 comes with python 3.10. To upgrade pip run ```python -m pip install --upgrade pip```

## Installation

This package contains the essential server and client component of Eclipse VOLTTRON framework. In order to start VOLTTRON in addition to this package(volttron-core) you also need volttron-lib-auth and volttron-lib-zmq. 

It is highly recommended you use a virtual environment for installing VOLTTRON.


```shell
python -m venv <directory name for your virtual env. for example .venv>
source .venv/bin/activate
export VOLTTRON_HOME=</path/to/volttron/home>
pip install volttron
```

Note: you can also run ```pip install volttron-zmq``` or install the three packages explicitly using ```pip install volttron-core volttron-lib-zmq volttron-lib-auth```

### Quick Start

 1. **Setup VOLTTRON_HOME** environment variable: export VOLTTRON_HOME=/path/to/volttron_home/dir

    **NOTE** This is mandatory if you have/had in the past, a monolithic    VOLTTRON version that used the default 
    VOLTTRON_HOME $HOME/.volttron. 
    **This modular version of VOLTTRON cannot work with volttron_home used by monolithic version of VOLTTRON(version 8.3 or earlier)**

 1. **Start the platform:**

    ```bash
    volttron -vv -l volttron.log &>/dev/null &
    ```

 1. **Install agents and optional libraries**:

    Each volttron agent is in it own repository. Each agent's repository will have its own readme with instructions on 
    how to install the agent and any optional libraries that could be used with the agent. But in general, agents should 
    be installed using vctl install command. 
    
    For example, 
    ```bash
    vctl install volttron-listener
    ```

    All libraries that the agent depends on will automatically get installed in your current python environment.
    
    **Optional Libraries**

    In addition to mandatory libraries that are automatically installed during agent install, some agents could have 
    optional features that are enabled or disabled based on availability of additional libraries. For example, an agent 
    could support unit conversion if the python pint library is installed in the python environment. In order to 
    install optional libraries use
    ```bash
    vctl install-lib <library name>
    ```
    
    Modular VOLTTRON uses poetry for dependency management. When VOLTTRON is started, it creates a poetry project 
    (pyproject.toml file) in VOLTTRON_HOME directory and uses that for keeping track of all installed packages. 
    For example, when you run ```vctl install volttron-listener``` an entry for that agent's package name and version 
    gets added to $VOLTTRON_HOME/pyproject.toml.
    If you are installing optional libraries, such as pint use ```vctl install-lib pint``` instead of pip install. 
    ```vctl install-lib``` will internally use poetry and poetry will check if the version of volttron-core 
    (and other librabries) in your current activated environment is compatible with requirements of the version 
    of library you are installing.

    | :warning: WARNING          |
    |:---------------------------|
    | You could use pip to install libraries, but pip will not check dependent library versions for compatibility and would simply overwrite packages in the current environment. <br /> <br /> For example, if you are running volttron-core version 2.0.0 and volttron-lib-bacnet-driver has dependency on  volttron-core version 1.0.0, ```pip install volttron-lib-bacnet-driver``` would overwrite volttron-core version 2.0.0 with version 1.0.0. However ```poetry add --directory $VOLTTRON_HOME volttron-lib-bacnet-driver``` will fail because of a version incompatibility error. |
    


 1. **View status of platform**

    ```bash
    vctl status
    ```

 1. **Shutdown the platform**

    ```bash
    vctl shutdown --platform
    ```
    
### Scaled VOLTTRON deployments

Multiple VOLTTRON instances can work together as a federated group and communicate with each other through publish/subscribe method. This is one way to achieve distributed scalable deployments. VOLTTRON also supports automated deployment using ansible. Please refer to 
[readthedocs](https://eclipse-volttron.readthedocs.io/en/latest/deploying-volttron/scaling-volttron.html) for more details

## Available Agents

- [volttron-agent-watcher](https://github.com/eclipse-volttron/volttron-agent-watcher/tree/v10)
- [volttron-dnp3-outstation](https://github.com/eclipse-volttron/volttron-dnp3-outstation/tree/v10)
- [volttron-emailer](https://github.com/eclipse-volttron/volttron-emailer/tree/v10)
- [volttron-bacnet-proxy](https://github.com/eclipse-volttron/volttron-bacnet-proxy/tree/v10)
- [volttron-platform-driver](https://github.com/eclipse-volttron/volttron-platform-driver/tree/v10)
- [volttron-listener](https://github.com/eclipse-volttron/volttron-listener/tree/v10)
- [volttron-postgresql-historian](https://github.com/eclipse-volttron/volttron-postgresql-historian/tree/v10)
- [volttron-sqlite-historian](https://github.com/eclipse-volttron/volttron-sqlite-historian/tree/v10)
- [volttron-log-statistics](https://github.com/eclipse-volttron/volttron-log-statistics/tree/v10)
- [volttron-sysmon](https://github.com/eclipse-volttron/volttron-sysmon/tree/v10)
- [volttron-threshold-detection](https://github.com/eclipse-volttron/volttron-threshold-detection/tree/v10)
- [volttron-topic-watcher](https://github.com/eclipse-volttron/volttron-topic-watcher/tree/v10)

## Libraries

- [volttron-lib-bacnet-driver](https://github.com/eclipse-volttron/volttron-lib-bacnet-driver/tree/v10)
- [volttron-lib-fake-driver](https://github.com/eclipse-volttron/volttron-lib-fake-driver/tree/v10)

## Links to important documentation

- [Known issues in this version](https://github.com/eclipse-volttron/volttron-core/labels/2.0.0rc0)
- [Important backward incompatible changes](backward_incompatible_features.md)
- Full VOLTTRON documentation available at [Eclilpse VOLTTRON Readthedocs](https://eclipse-volttron.readthedocs.io)

## Contributing to VOLTTRON

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository.

Please see [developing_on_modular.md](DEVELOPING_ON_MODULAR.md) document for developing your agents against volttron.

## Disclaimer Notice

This material was prepared as an account of work sponsored by an agency of the
United States Government.  Neither the United States Government nor the United
States Department of Energy, nor Battelle, nor any of their employees, nor any
jurisdiction or organization that has cooperated in the development of these
materials, makes any warranty, express or implied, or assumes any legal
liability or responsibility for the accuracy, completeness, or usefulness or any
information, apparatus, product, software, or process disclosed, or represents
that its use would not infringe privately owned rights.

Reference herein to any specific commercial product, process, or service by
trade name, trademark, manufacturer, or otherwise does not necessarily
constitute or imply its endorsement, recommendation, or favoring by the United
States Government or any agency thereof, or Battelle Memorial Institute. The
views and opinions of authors expressed herein do not necessarily state or
reflect those of the United States Government or any agency thereof.


