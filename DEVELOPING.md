
## Development of VOLTTRON

### Environment

#### VOLTTRON_HOME
Setup VOLTTRON_HOME environment variable: export VOLTTRON_HOME=/path/to/volttron_home/dir. 

This is madatory if you have/had in the past, a monolithic VOLTTRON version that used the default VOLTTRON_HOME $HOME/.volttron. **Modular version of VOLTTRON cannot work with volttron_home used by monolithic version of VOLTTRON(version 8.3 or earlier)**

#### Poetry
VOLTTRON uses [Poetry](https://python-poetry.org/), a dependency management and packaging tool for Python. If you don't have Poetry installed on your machine, follow [these steps](https://python-poetry.org/docs/#installation) to install it on your machine.

To check if Poetry is installed, run `poetry --version`. If you receive the error 'command not found: poetry', add the following line to your '~/.bashrc' script: ```export PATH=$PATH:$HOME/.local/bin```.


#### Recommended configuration for poetry

By default, poetry creates a virtual environment in {cache-dir}/virtualenvs. To configure 'poetry' to create the virtualenv inside this project's root directory, run the following command:

[```poetry config virtualenvs.in-project true```](https://python-poetry.org/docs/configuration)

### Setup

 1. Clone the repository
    ```bash
    git clone https://github.com/eclipse-volttron/volttron-core -b develop
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

In order to run VOLTTRON from within an ide the recommended way is to run the platform using the modules

 ```bash
 > poetry shell
 > python -m volttron.server -vv -l volttron.log &
 > python -m volttron.commands.control -vv status
```

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository.

Happy Editing!