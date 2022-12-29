# VOLTTRON Docker Image

This is the readme for the VOLTTRON docker image. 


## Minimal Execution

A volttron is able to be executed directly from docker.  This will create a running volttron, but will not
persist after the container stops.

```bash
# Starts a volttron in the background
docker run -d --name volttron --rm -it eclipsevolttron/volttron:v10
```

```bash
docker logs volttron
```

```bash
# creates a bash script inside the container.
docker exec --name volttron bash

vctl status

vctl install volttron-listener

vctl status

vctl shutdown --platform
```

## Persisting the VOLTTRON_HOME 

```bash
# Starts a volttron persisting volttron home.
docker run -d -v $PWD/vhome:/home/volttron/.volttron \
    --name volttron --rm -it eclipsevolttron/volttron:v10
```

## Initialization of Platform

```bash
# Starts a volttron persisting volttron home.
docker run -d -v $PWD/example/config:/config \
    -v $PWD/vhome:/home/volttron/.volttron \
    -e 'PLATFORM_CONFIG=/config/example_platform_config.yml' \
    --name volttron --rm -it eclipsevolttron/volttron:v10
```
