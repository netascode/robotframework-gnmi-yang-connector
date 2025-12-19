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
