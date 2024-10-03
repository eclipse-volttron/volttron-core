Eclipse VOLTTRON™ (VOLTTRON/volttron) is an open source platform for distributed sensing and control. The platform provides services for collecting and storing data from buildings and devices and provides an environment for developing applications which interact with that data.

[![Eclipse VOLTTRON™](https://img.shields.io/badge/Eclips%20VOLTTRON--red.svg)](https://volttron.readthedocs.io/en/latest/)
![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
[![Pytests](https://github.com/eclipse-volttron/volttron-core/actions/workflows/run-tests.yml/badge.svg)](https://github.com/eclipse-volttron/volttron-core/actions/workflows/run-tests.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron.svg)](https://pypi.org/project/volttron/)
## Pre-requisites

- git >= 2.25

- poetry >= 1.2.2

- python >= 3.10

- pip >= 24.0

  Note- Ubuntu 22.04 comes with python 3.10. To upgrade pip run ```python -m pip install --upgrade pip```
 
## Installation
This package is the core volttron server, client and utilities. in order to successfully start volttron at a minimum you would need a volttron message bus(volttron-lib-zmq) and volttron authentication library(volttron-lib-auth). You can install these as three separate steps or use the wrapper (volttron-zmq) that pulls all three packages

It is highly recommended you use a virtual environment for installing volttron.

```shell
python -m venv <directory name for your virtual env. for example .vemv>
source .venv/bin/activate
export VOLTTRON_HOME=</path/to/volttron/home>
pip install volttron-zmq
```

Note you can also run ```pip install volttron-core volttron-lib-zmq volttron-lib-auth```

### Quick Start

 1. **Setup VOLTTRON_HOME** environment variable: export VOLTTRON_HOME=/path/to/volttron_home/dir 
 
    **NOTE** This is madatory if you have/had in the past, a monolithic    VOLTTRON version that used the default VOLTTRON_HOME $HOME/.volttron. **This modular version of VOLTTRON cannot work with volttron_home used by monolithic version of VOLTTRON(version 8.3 or earlier)**
 
 2. **Start the platform:**
    
    ```bash
    volttron -vv -l volttron.log &>/dev/null &
    ```

 4. **Install agents**: 
    For example, 
    ```bash
    vctl install volttron-listener --start
    ```

 5. **Install any optional libraries that your agents need:**
    
    Monolithic VOLTTRON uses poetry for dependency management. When VOLTTRON is started, it creates a poetry project (pyproject.toml file) in VOLTTRON_HOME directory and use that for keeping track of all installed packages. For example, when you ran "vctl install volttron-listener" an entry for that agent's package name and version gets added to $VOLTTRON_HOME/pyproject.toml.

    If you are installing optional librabries, such as volttron-lib-bacnet-driver use poetry instead of pip
    ```bash
    poetry add --directory $VOLTTRON_HOME volttron-lib-bacnet-driver
    ```

    Poetry will check if the version of volttron-core (and other librabries) in your current activated environment is compatible with requirements of the version of volttron-lib-bacnet-driver you are installing.

    **Warning:** You could use pip to install librabries, but pip will not check dependent library versions for compatibility and simply overwrite packages in the current environment. For example, if you are running volttron-core version 2.0.0 and volttron-lib-bacnet-driver has dependency on volttron-core version 1.0.0, ```pip install volttron-lib-bacnet-driver``` would overwrite volttron-core version 2.0.0 with version 1.0.0. However ```poetry add --directory $VOLTTRON_HOME volttron-lib-bacnet-driver``` will fail with version incompatibility error
    
 4. View status of platform
    ```bash
    vctl status
    ```

 5. Shutdown the platform
    ```bash
    vctl shutdown --platform
    ```

## Links to important documentation
 - [Known issues in this version](https://github.com/eclipse-volttron/volttron-core/labels/2.0.0rc0) 
 - [Important backward incompatible changes](backward_incompatible_features.md)
 - Full VOLTTRON documentation available at [VOLTTRON Readthedocs](https://volttron.readthedocs.io)

## Contributing to VOLTTRON

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository.

Please see [developing_on_modular.md](DEVELOPING_ON_MODULAR.md) document for developing your agents against volttron.

# Disclaimer Notice

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
