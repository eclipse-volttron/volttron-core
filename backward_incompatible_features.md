
# Modular VOLTTRON backward incompatible features

Modular VOLTTRON (version > 9)  is a complete redesign of the previous monolithic versions of VOLTTRON (version <=9). 
The new modular design of VOLTTRON enables high level of flexibility and customization for the user, but in order to achieve this, we had to break backward compatibility with the older monolithic VOLTTRON. 
  
The following highlights the key differences. For details about each of these features, please refer to [volttron readthedocs page](https://eclipse-volttron.readthedocs.io/en/latest/)

1. The primary VOLTTRON platform code is split into the following repositories
   - volttron-core(this repository)
   -  [volttron-lib-auth](https://github.com/eclipse-volttron/volttron-lib-auth)
   -  [volttron-lib-zmq](https://github.com/eclipse-volttron/volttron-lib-zmq)

    All these are available as packages to be installed from pypi (or test-pypi if you want to get at latest development versions). A wrapper package [volttron-zmq](https://pypi.org/project/volttron-zmq)  can be used to install all three packages with a single ```pip install volttron-zmq``` command

3. Each agent and library is now housed in its own repository and published to pypi as a separate package - for example [volttron-listener source code repository](https://github.com/eclipse-volttron/volttron-listener]) and [volttron-listener pypi package](https://pypi.org/project/volttron-listener/)
   
4. VOLTTRON now uses **Poetry for dependency management**. This is essential for ensuring there is no version mismatch in the set of libraries installed and working together in a given python environment. When VOLTTRON starts for the first time for a given VOLTTRON_HOME, it creates a poetry project in VOLTTRON_HOME and uses the pyproject.toml to manage list of libraries.
   So when adding optional libraries to your environment, **use ```poetry add --directory <lib>``` instead of ```pip install <lib>```**. Example: ```poetry add --directory $VOLTTRON_HOME volttron-lib-bacnet-driver```.
   Note: Next version would add a vctl install-lib command that can be used instead of poetry add --directory (https://github.com/eclipse-volttron/volttron-core/issues/221)
   
6. The default execution directory for VOLTTRON process is $VOLTTRON_HOME and the default execution directory for agent is $VOLTTRON_HOME/agents/<vip-id>. See issue https://github.com/eclipse-volttron/volttron-core/issues/167
   
7. The structure of directories in VOLTTRON_HOME is different from earlier version, hence **modular volttron cannot work with volttron home created by monolithic volttron**
   
8.  Authentication and Authorization are now two separate functionalities and entries related to authentication and authorization are persisted in different files in $VOLTTRON_HOME
   
9.  Authorization is now specific to individual instances of an agent. Agent capabilities and access restrictions are NOT part of source code anymore. (**No @RPC.allow decorator** available for agent source code). Authorizations are only assigned using vctl authz commands or entries in $VOLTTRON_HOME/authz.json
    
11.   Authorization does not depend on arbitrary capability strings and is defined using actual ```<vipid>.<method name>```

12.   Topics can be both read and write protected. Topic protection is also done using vctl authz commands. There is **no separate protected_topics.json**
    
14.   The Platform Driver agent has been redesigned significantly and includes many new features to improve polling, group points, etc. Please refer to [the platform driver agent's documentation](https://github.com/eclipse-volttron/volttron-platform-driver/blob/v10/README.md) for more details.
    
16.  **The platform driver now by default publishes to topics of the format ```devices/<campus>/<building>/<device>/multi```** instead of ```devices/<campus>/<building>/<device>/all```.
    
18.  The basehistorian now by default subscribes to ```devices/.*/multi``` instead of ```devices/.*/all```

   
