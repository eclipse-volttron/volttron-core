# Developing on Modular Eclipse VOLTTRON™

The following documentation steps through the process of setting up your environment to start
developing on modular Eclipse VOLTTRON™ (VOLTTRON/volttron).

There are requirements in order to follow this README. The following requirements should be installed system-wide, 
so they are available to be used throughout the README.

* Poetry >= 1.2.2

## Installing poetry

VOLTTRON uses [Poetry](https://python-poetry.org/), a dependency management and packaging tool for Python. If you don't have Poetry installed on your machine, follow [these steps](https://python-poetry.org/docs/#installation) to install it on your machine.

To check if Poetry is installed, run `poetry --version`. If you receive the error 'command not found: poetry', add the following line to your '~/.bashrc' script: ```export PATH=$PATH:$HOME/.local/bin``` and restart your shell.

### Recommended configuration for poetry

By default, poetry creates a virtual environment in {cache-dir}/virtualenvs. To configure 'poetry' to create the virtualenv inside this project's root directory, run the following command:

[```poetry config virtualenvs.in-project true```](https://python-poetry.org/docs/configuration)


# Development

##  New Agent 
* Please use the tool [copier-poetry-volttron-agent](https://github.com/VOLTTRON/copier-poetry-volttron-agent/tree/develop) to create a new agent. 

## Existing Agent

The recommended development path is outlined below:

* Fork the agent repository on Github
* Clone the repository in your local environment
* Setup the environment using poetry

```shell
poetry install 
```

* Create a working branch off of the 'develop' branch
* Make a code change
* Run tests

```shell
poetry run pytest tests/
```
* Create a Pull Request (PR)
  * Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository.
  * Go to your forked Github repository in your browser and create a pull request.  

## Building a Wheel

To build a wheel from this project, execute the following command at the root level of this repository:

```shell
poetry build
```

The wheel and source distribution will be located in the ```./dist/``` directory.

## Bumping version number of project

To bump the version number of the project execute one of the following.

```shell
# patch, minor, major, prepatch, preminor, premajor, prerelease

# use patch
user@path$ poetry patch

# output
Bumping version from 0.2.0-alpha.0 to 0.2.0

# use prepatch
user@path$ poetry version prepatch

# output
Bumping version from 0.2.0 to 0.2.1-alpha.0
```

## Testing 

If starting from an existing agent, when running poetry install without any arguments will install the volttron-testing package in your environment.

If a new agent, to write tests against volttron-testing, install [`volttron-testing`](https://github.com/eclipse-volttron/volttron-testing/tree/develop) as a dev dependency. Use poetry to install `volttron-testing` into your environment:

```shell
poetry add volttron-testing --group dev
```

## Tests

[`volttron-testing`](https://github.com/eclipse-volttron/volttron-testing/tree/develop) is Volttron's testing framework to support writing tests on Modular Volttron. It offers several tools that you can use to write tests. 

### Unit Tests

Use [`TestServer`](https://github.com/eclipse-volttron/volttron-testing/blob/develop/src/volttrontesting/server_mock.py) to create the testing environment for unit tests. For an example of a unit test, 
see the unit tests created for [volttron-listener](https://github.com/eclipse-volttron/volttron-listener/blob/develop/tests/test_agent_workings.py)


### Integration Tests

Use [`PlatformWrapper`](https://github.com/eclipse-volttron/volttron-testing/blob/develop/src/volttrontesting/platformwrapper.py) to create the testing environment for integration tests. For an example of an integration test, 
see the integration tests created for [volttron-listener](https://github.com/eclipse-volttron/volttron-listener/blob/develop/tests/test_integration.py)
