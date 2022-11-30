# Quickstart Deployment Guide

The following document shows how to install and configure the platform driver with a fake driver, the sqlite-historian and a listener agent.

## Requirements

There are system level requirements that must be met before installing VOLTTRON.  One can install on ubuntu using the following commands:

```shell
sudo apt-get update
sudo apt-get install build-essential libffi-dev python3-dev python3-venv openssl libssl-dev libevent-dev git
```

## Environment

Depending on how one wants to deploy VOLTTRON an environment must be built/created in order to be able to execute python code.  It is recommended practice for a virtual environment to be created specifically for VOLTTRON.

 1. As a non-root user a folder to contain the configuration files for your deployment.
    ```shell
    > mkdir deployment && cd deployment
    ```
 1. Create and activate the virtual environment for your volttron instance
    ```shell
    > python3 -m venv env
    > source env/bin/activate
    ```

## Deployment

 1. Install and start the VOLTTRON instance.
    ```shell
    (env)> pip install volttron
    # Note use -v for less verbose logging.
    (env)> volttron -vv -l volttron.log &>/dev/null &
    ```
 1. Verify installation and log output
    ```shell
    (env)> vctl status
    No installed Agents found
    (env)> tail volttron.log
    ```

### Agent and Library Installation

 1. Install a volttron-listener agent to the VOLTTRON instance.  This will allow the message traffic on the VOLTTRON bus to be output to the log file.
    ```shell
    (env)> vctl install volttron-listener
    ```
 1. Create a fake.config file
    ```shell
    cat <<EOT >> fake.config.json
    {
    "driver_config": {},
    "registry_config": "config://fake.csv",
    "interval": 5,
    "timezone": "US/Pacific",
    "heart_beat_point": "Heartbeat",
    "driver_type": "fake",
    "publish_breadth_first_all": false,
    "publish_depth_first": false,
    "publish_breadth_first": false
     }
    EOT
    ```
 1. Create a fake.csv file to hold the points for publishing.
    ```shell
    cat <<EOT >> fake.csv
    Point Name,Volttron Point Name,Units,Units Details,Writable,Starting Value,Type,Notes
    EKG,EKG,waveform,waveform,TRUE,sin,float,Sine wave for baseline output
    Heartbeat,Heartbeat,On/Off,On/Off,TRUE,0,boolean,Point for heartbeat toggle
    OutsideAirTemperature1,OutsideAirTemperature1,F,-100 to 300,FALSE,50,float,CO2 Reading 0.00-2000.0 ppm
    SampleWritableFloat1,SampleWritableFloat1,PPM,1000.00 (default),TRUE,10,float,Setpoint to enable demand control ventilation
    SampleLong1,SampleLong1,Enumeration,1 through 13,FALSE,50,int,Status indicator of service switch
    SampleWritableShort1,SampleWritableShort1,%,0.00 to 100.00 (20 default),TRUE,20,int,Minimum damper position during the standard mode
    SampleBool1,SampleBool1,On / Off,on/off,FALSE,TRUE,boolean,Status indidcator of cooling stage 1
    SampleWritableBool1,SampleWritableBool1,On / Off,on/off,TRUE,TRUE,boolean,Status indicator
    OutsideAirTemperature2,OutsideAirTemperature2,F,-100 to 300,FALSE,50,float,CO2 Reading 0.00-2000.0 ppm
    SampleWritableFloat2,SampleWritableFloat2,PPM,1000.00 (default),TRUE,10,float,Setpoint to enable demand control ventilation
    SampleLong2,SampleLong2,Enumeration,1 through 13,FALSE,50,int,Status indicator of service switch
    SampleWritableShort2,SampleWritableShort2,%,0.00 to 100.00 (20 default),TRUE,20,int,Minimum damper position during the standard mode
    SampleBool2,SampleBool2,On / Off,on/off,FALSE,TRUE,boolean,Status indidcator of cooling stage 1
    SampleWritableBool2,SampleWritableBool2,On / Off,on/off,TRUE,TRUE,boolean,Status indicator
    OutsideAirTemperature3,OutsideAirTemperature3,F,-100 to 300,FALSE,50,float,CO2 Reading 0.00-2000.0 ppm
    SampleWritableFloat3,SampleWritableFloat3,PPM,1000.00 (default),TRUE,10,float,Setpoint to enable demand control ventilation
    SampleLong3,SampleLong3,Enumeration,1 through 13,FALSE,50,int,Status indicator of service switch
    SampleWritableShort3,SampleWritableShort3,%,0.00 to 100.00 (20 default),TRUE,20,int,Minimum damper position during the standard mode
    SampleBool3,SampleBool3,On / Off,on/off,FALSE,TRUE,boolean,Status indidcator of cooling stage 1
    SampleWritableBool3,SampleWritableBool3,On / Off,on/off,TRUE,TRUE,boolean,Status indicator
    HPWH_Phy0_PowerState,PowerState,1/0,1/0,TRUE,0,int,Power on off status
    ERWH_Phy0_ValveState,ValveState,1/0,1/0,TRUE,0,int,power on off status
    EKG_Sin,EKG_Sin,1-0,SIN Wave,TRUE,sin,float,SIN wave
    EKG_Cos,EKG_Cos,1-0,COS Wave,TRUE,sin,float,COS wave
    EOT
    ```
 1. Install the fake driver library into the python environment
    ```shell
    # Note this is not an agent, but a library that extends from volttron-lib-base-driver.  
    # Libraries allow the volttron-platform-driver agent to interact with devices without the volttron-platform-driver
    # knowing anything about the device protocol itself. 
    (env)> pip install volttron-lib-fake-driver
    ```
 1. Install the volttron-platform driver to the VOLTTRON instance.
    ```shell
    (env)> vctl install volttron-platform-driver --vip-identity platform.driver --start 
    ```
 1. Store the configuration files into the platform.driver's config store
    ```shell
    (env)> vctl config store platform.driver devices/campus/building/fake fake.config.json
    (env)> vctl config store platform.driver fake.csv fake.csv --csv
    ```
 1. Install a volttron-sqlite-historian
    ```shell
    (env)> vctl install volttron-sqlite-historian --vip-identity platform.historian --start
    ```

## Finding Agents/Libraries

All agents and libraries are stored on [pypi](https://pypi.org/).  Searching for `volttron` will give you all of the deployed agents and libraries available.

## Development

For information on developing new agents and libraries please see (DEVELOPING_ON_MODULAR.md)[DEVELOPING_ON_MODULAR.md]