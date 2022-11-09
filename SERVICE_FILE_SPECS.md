# Service File Specifications

## Location

The location of the service file shall be within the $VOLTTRON_HOME and have the 
name of service_config.yml

## Content

Each service referenced in the file allows the starting of the service
during the start-up of the VOLTTRON server.  This is ideal for server
side services such as web.  The following is examples of services that
are configured.

```yaml
---
# service_config.yml file in $VOLTTRON_HOME/service_config.yml

# module/namespace for where the service is located
volttron.services.control:
  # Priority ordering 0-100 with 0 being higher
  # priority default is 50
  priority: 10
  # enable/disable loading of this service.
  enabled: true
  # key word arguments passed to the service
  # during creation of the service
  kwargs:
    agent-monitor-frequency: 10
    
volttron.services.auth:
  priority: 12
  # path to namespace where this can be loaded
  path: /repos/volttron-lib-zmq/src

```