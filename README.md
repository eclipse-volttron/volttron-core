VOLTTRON™ is an open source platform for distributed sensing and control. The platform provides services for collecting and storing data from buildings and devices and provides an environment for developing applications which interact with that data.

[![Pytests](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml/badge.svg)](https://github.com/VOLTTRON/volttron-core/actions/workflows/run-tests.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron.svg)](https://pypi.org/project/volttron-core/)

## Installation

```basy
> pip install volttron
```

### Quick Start

1. Start the platform
   ```bash
   > volttron -vv -l volttron.log &>/dev/null &
   ```
1. Install listener agent
   ```bash
   > vctl install volttron-listener
   ```
1. View status of platform
   ```bash
   > vctl status
   ```
1. Shutdown the platform
   ```bash
   > vctl shutdown --platform
   ```

Full documentation available at [VOLTTRON Readthedocs](https://volttron.readthedocs.io)

## Contributing to VOLTTRON

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository. 

## Development of VOLTTRON

### Environment

VOLTTRON uses [Poetry](https://python-poetry.org/), a dependency management and packaging tool for Python. If you don't have Poetry installed on your machine, follow [these steps](https://python-poetry.org/docs/#installation) to install it on your machine.

To check if Poetry is installed, run `poetry --version`. If you receive the error 'command not found: poetry', add the following line to your '~/.bashrc' script: ```export PATH=$PATH:$HOME/.poetry/bin```.

#### Recommended configuration for poetry

By default, poetry creates a virtual environment in {cache-dir}/virtualenvs. To configure 'poetry' to create the virtualenv inside this project's root directory, run the following command:

[```poetry config virtualenvs.in-project true```](https://python-poetry.org/docs/configuration)

### Setup
1. Clone the repository
   ```bash
   git clone https://github.com/VOLTTRON/volttron-core -b develop
   ```
1. cd into volttron-core directory
   ```bash
    cd volttron-core
    ```
1. Install volttron into the current directory
   ```bash
   poetry install 
   ```
1. Run tests 
   ```bash
   poetry run pytest
   ```
1. Activate environment (removes the need for add poetry run to all commands)
   ```bash
   poetry shell
   ```
1. Run volttron
   ```bash
   volttron -vv -l volttron.log &>/dev/null &
   ```
### Using modules to run VOLTTRON

 ```bash
 > poetry run python3 -m volttron.server -vv -l volttron.log & 
 > poetry run python3 -m volttron.commands.control -vv status 
```

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository. 
 
Happy Editing!
