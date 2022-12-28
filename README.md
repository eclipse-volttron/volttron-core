VOLTTRON™ is an open source platform for distributed sensing and control. The platform provides services for collecting and storing data from buildings and devices and provides an environment for developing applications which interact with that data.

[![Pytests](https://github.com/eclipse-volttron/volttron-core/actions/workflows/run-tests.yml/badge.svg)](https://github.com/eclipse-volttron/volttron-core/actions/workflows/run-tests.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron.svg)](https://pypi.org/project/volttron/)

## Installation

It is recommended to use a virtual environment for installing volttron.

```shell
python -m venv env
source env/bin/activate

pip install volttron
```

### Quick Start

 1. Setup VOLTTRON_HOME environment variable: export VOLTTRON_HOME=/path/to/volttron_home/dir 
 
    **NOTE** This is madatory if you have/had in the past, a monolithic    VOLTTRON version that used the default VOLTTRON_HOME $HOME/.volttron. This modular version of VOLTTRON cannot work with volttron_home used by monolithic version of VOLTTRON(version 8.3 or earlier)
 
 2. Start the platform
    ```bash
    > volttron -vv -l volttron.log &>/dev/null &
    ```

 3. Install listener agent
    ```bash
    > vctl install volttron-listener --start
    ```

 4. View status of platform
    ```bash
    > vctl status
    ```

 5. Shutdown the platform
    ```bash
    > vctl shutdown --platform
    ```

Full VOLTTRON documentation available at [VOLTTRON Readthedocs](https://volttron.readthedocs.io)

## Contributing to VOLTTRON

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository.

Please see [developing_on_modular.md](DEVELOPING_ON_MODULAR.md) document for developing your agents against volttron.
