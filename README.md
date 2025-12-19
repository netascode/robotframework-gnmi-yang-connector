# GnmiYangConnector

A gNMI and YANG connector library for Robot Framework.

## Overview

GnmiYangConnector provides a Robot Framework library for interacting with network devices using gNMI (gRPC Network Management Interface) protocol and YANG data models.

## Features

- gNMI protocol support
- Robot Framework keyword library
- Python 3.10+ support

## Installation

```bash
pip install robotframework-gnmi-yang-connector
```

## Available Keywords

GnmiYangConnector provides the following Robot Framework keywords:

### gNMI Keywords

- **gNMI connect to device** - Establish a gNMI connection to a device using pyATS testbed configuration
- **gNMI close session** - Close gNMI session to a specific device
- **gNMI close all sessions** - Close all active gNMI sessions
- **gNMI get capabilities** - Retrieve device capabilities via gNMI
- **gNMI get** - Perform gNMI GET operation to retrieve configuration or state data
- **gNMI set** - Perform gNMI SET operation to update, replace, or delete configuration
- **gNMI subscribe** - Subscribe to telemetry data streams using gNMI

### gNOI Keywords (gRPC Network Operations Interface)

- **gNOI ping** - Execute ping operation on the device
- **gNOI traceroute** - Execute traceroute operation on the device
- **gNOI system time** - Retrieve system time from the device
- **gNOI reboot** - Trigger a device reboot

### gRPC Keywords

- **gRPC action** - Execute custom gRPC actions on protocol buffers with provided parameters

## Usage Example

Here's a basic example of using the library:

```robotframework
*** Settings ***
Library           pyats.robot.pyATSRobot
Library           GnmiYangConnector

Suite Setup       use testbed "${TESTBED}"
Suite Teardown    gNMI close all sessions

*** Variables ***
${TESTBED}       ${CURDIR}/testbed.yaml
${DEVICE}        xr1

*** Test Cases ***
Get Capabilities
    [Setup]    gNMI connect to device    ${DEVICE}
    ${caps}=    gNMI get capabilities    ${DEVICE}
    Log   ${caps}

Perform Get Operation
    [Setup]    gNMI connect to device    ${DEVICE}
    VAR   ${prefix}    Cisco-IOS-XR-um-interface-cfg
    VAR   @{path}    ${prefix}:interfaces
    ${response}=    gNMI get    ${DEVICE}    ${path}    datatype=CONFIG
    Log   ${response}
```

For more examples, see the [examples](examples/) directory.

## License

See LICENSE file for details.
