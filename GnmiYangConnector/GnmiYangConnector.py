# Copyright (c)  Cisco Systems, Inc. - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential

import os
import json
import subprocess
import re
import base64
from random import randint
from google.protobuf.json_format import MessageToDict
from robot.api import logger
from robot.api.deco import keyword
from robot.utils import is_falsy
from robot.libraries.BuiltIn import BuiltIn, RobotNotRunningError

import json_duplicate_keys
from yang.connector import proto
from yang.connector import gnmi as yang_gnmi
from genie.libs.sdk.triggers.blitz import gnmi_util

from .spec import ems_grpc_pb2
from .spec import ems_grpc_pb2_grpc
from .utils import extract_creds_from_device


class GnmiException(Exception):
    pass


class GnmiYangConnector:
    """
    Class used to create keywords for gNMI connections.


    """

    ROBOT_LIBRARY_SCOPE = "GLOBAL"
    ROBOT_LIBRARY_DOC_FORMAT = "reST"

    def __init__(self):
        """ """
        self.timeout = 60
        self.gnmi_sessions = {}
        self.notification_timeout = 30
        self.subscription_streams = {}

        try:
            self.pyatsRobot = BuiltIn().get_library_instance("pyats.robot.pyATSRobot")
        except RuntimeError:
            raise RuntimeError(
                "Missing mandatory 'Library    pyats.robot.pyATSRobot' in the Setting section"
            )
        except RobotNotRunningError:
            # ignore error, for example during libdoc generation or unit testing
            pass

    @property
    def testbed(self):
        """
        Reference to the currently loaded pyats testbed.
        """
        return self.pyatsRobot.testbed

    def _get_gnmi_device_details(self, device: str, via: str):
        if device in self.testbed.devices:
            dev = self.testbed.devices[device]
        else:
            raise KeyError(
                f'Device "{device}" is not in the testbed. Please add the device'
                f" to the testbed YAML file."
            )
        try:
            fqdn = dev.connections.gnmi.ssl_name_override
            port = dev.connections.gnmi.get("port", 54700)
            root_certificate = dev.connections.gnmi.root_certificate
            (username, password) = extract_creds_from_device(device=dev, connection=via)
        except AttributeError as e:
            raise AttributeError(
                f"gNMI connection details missing in testbed.yaml: {e}"
            ) from e

        return username, password, fqdn, port, root_certificate

    @keyword(r"gNMI connect to device")
    def gnmi_connect_to_device(self, device: str, via="gnmi"):
        """
        Connect to a device with gNMI using pyATS yang.connector, with connection passed (default: gnmi) in testbed.yaml

        Sample testbed.yaml connector gnmi:

            .. code::

                devices:
                  PE1:
                    connections:
                      gnmi:
                        class: yang.connector.Gnmi
                        protocol: gnmi
                        host: 10.1.2.3
                        port: 57344
                        username: user1
                        password: user1Password
                        ca_cert_file: CA.cer
                        root_certificate: 'certs/CA.cer'
                        private_key: 'certs/PE1.key'
                        certificate_chain: 'certs/PE1.crt'
                        ssl_name_override: 'PE1.example.com'

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: via: (str) optional connection name from testbed.yaml (default is 'gnmi')
        :Returns:
            :returns: (Gnmi) gnmi session object
        :Raises:
            :raises: (KeyError) if device not in testbed.yaml
            :raises: (AttributeError) if device parameters are missing in testbed YAML file
        :Example:

            .. code:: robotframework

                gNMI connect to device    ${device}
                gNMI connect to device    ${device}    via=my_gnmi

        **NOTE**: This keyword ignores looking for ssh keys in default locations such as ~/.ssh/id_* but instead relies
        on the keyfile param in the testbed.yaml file
        While this keyword supports a 'via' argument, not more than one connection to any given device
        can be established at a time. The keyword logs a warning if multiple connections are attempted.
        You must close the gNMI connection before opening a new with a different via/connection name.
        """
        if device in self.gnmi_sessions:
            logger.info(
                f'gNMI connection to device "{device}" is already established '
                f"(via={self.gnmi_sessions[device].via}), no action is performed"
            )
            return
        if device not in self.testbed.devices:
            raise KeyError(
                f'Device "{device}" is not in the testbed. Please add the device'
                f" to the testbed YAML file."
            )
        gnmi_device = self.testbed.devices[device]
        gnmi_device.connect(via=via, alias=via)
        gnmi_session = getattr(gnmi_device, via)
        if not isinstance(gnmi_session, yang_gnmi.Gnmi):
            raise AttributeError(
                f'connection to device "{device}" via "{via}" is not a gNMI connection'
            )
        self.gnmi_sessions[device] = gnmi_session
        logger.info(
            f"gNMI session established for device {device}, session: {gnmi_session}"
        )
        return gnmi_session

    def _get_gnmi_session(self, device):
        if device not in self.gnmi_sessions:
            raise ValueError(
                f'gNMI session to "{device}" does not exist. Please connect to device first.'
            )
        return self.gnmi_sessions[device]

    @keyword("gNMI close session")
    def gnmi_close_session(self, device: str):
        """
        Close gNMI session to target device

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
        :Returns:
            :returns: None
        :Raises:
            :raises: None

        :Example:

            .. code:: robotframework

                gNMI close session    ${device}

        """
        if device in self.gnmi_sessions:
            self._close_session(device)
        else:
            logger.info(
                f"No existing gNMI connection to device {device}. No action is performed."
            )

    def _close_session(self, device):
        gnmi_session = self._get_gnmi_session(device)
        logger.info(
            f'Close gNMI session for device "{device}", session: {gnmi_session}'
        )
        gnmi_session.disconnect()
        self.gnmi_sessions.pop(device)

    @keyword("gNMI close all sessions")
    def gnmi_close_all_sessions(self):
        """
        gNMI close all sessions

        :Parameters: None
        :Returns:
            :returns: None
        :Raises:
            :raises: (GnmiException) if device or testbed details are missing

        :Example:

            .. code:: robotframework

                gNMI close all sessions

        """
        logger.info(f"Close all sessions {self.gnmi_sessions}")
        _sessions = self.gnmi_sessions.copy()
        for device in _sessions:
            self._close_session(device)

    @keyword("gNMI get capabilities")
    def gnmi_get_capabilities(self, device: str):
        """
        gNMI get capabilities

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
        :Returns:
            :returns: (dict) device capabilities
        :Raises:
            :raises: (GnmiException) if device or testbed details are missing

        :Example:

            .. code:: robotframework

                gNMI get capabilities    ${device}

        """
        gnmi_session = self._get_gnmi_session(device)
        return gnmi_session.capabilities()

    @staticmethod
    def _gnmi_get_return_values(raw_data):
        """
        Extracts values from a gnmi_pb2.GetResponse object

        :param: (gnmi_pb2.GetResponse) response from Get
        :returns: (list) List of values
        """
        resp_json = []
        for i, notification in enumerate(raw_data.notification):
            logger.debug(f"===== notification[{i}] ======")
            for j, update in enumerate(notification.update):
                logger.debug(f"===== notification[{i}].update[{j}] ======")
                if update.val.json_ietf_val != b"":
                    val = json.loads(update.val.json_ietf_val)
                    logger.debug(
                        f"gNMI.get notification response val:\n{json.dumps(val, indent=2)}"
                    )
                    resp_json.append(val)
        return resp_json

    @staticmethod
    def _gnmi_get_return_full_proto_message(raw_data):
        """
        Extracts notifications from a gnmi_pb2.GetResponse object

        :param: (gnmi_pb2.GetResponse) response from Get
        :returns: (list) List of dict, full response with context
        """
        resp_json = MessageToDict(raw_data)
        notifications = resp_json.get("notification", [])
        processed_notifications = []
        for notification in notifications:
            update = notification.get("update", [])
            for item in update:
                val = item.get("val", {}).get("jsonIetfVal")
                if val:
                    decoded_bytes = base64.b64decode(val)
                    decoded_str = decoded_bytes.decode("utf-8")
                    item["val"] = json.loads(decoded_str) if decoded_str else None
                processed_notifications.append({"update": item})
        return processed_notifications

    @keyword("gNMI get")
    def gnmi_get(
        self,
        device: str,
        path: list | None = None,
        datatype: str = "ALL",
        encoding: str = "JSON_IETF",
        full_response: bool = False,
    ):
        """
        gNMI get

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: path: (list) list of path
            :param: datatype: one of ALL (default), CONFIG, STATE
            :param: encoding: one of JSON, JSON_IETF (default), PROTO
            :param: full_response: (bool) True for full proto Message response, False (default) for values only
        :Returns:
            :returns: (list) List of Values if full_response=${FALSE} (default) or list of dict (if full_response=${TRUE})
        :Raises:
            :raises: None

        :Example:

            .. code:: robotframework

                gNMI get    ${device}    path=${path_list}    datatype=STATE    encoding=JSON_IETF

        """
        logger.debug(
            f"gNMI get device: {device} path: {path}, datatype: {datatype}, encoding: {encoding}, "
            f"full_response: {full_response}"
        )
        gnmi_session = self._get_gnmi_session(device)
        request = proto.gnmi_pb2.GetRequest()
        request.type = proto.gnmi_pb2.GetRequest.DataType.Value(datatype)
        request.encoding = proto.gnmi_pb2.Encoding.Value(encoding)
        if path is None:
            logger.info("gNMI get, path is empty")
            path = []
        for path_item in path:
            gnmi_path = gnmi_util.GnmiMessageConstructor.parse_xpath_to_gnmi_path(
                path_item
            )
            request.path.append(gnmi_path)

        raw_data = gnmi_session.get(request)

        # if full_response required, then return full proto Message with context, instead of values only (jsonIetfVal)
        if is_falsy(full_response):
            return self._gnmi_get_return_values(raw_data)
        else:
            return self._gnmi_get_return_full_proto_message(raw_data)

    @staticmethod
    def _proto_encode(path, value, encoding):
        if path is None:
            return []
        logger.debug(f"_proto_encode: --- path: {type(path)} {path}")
        logger.debug(f"    value: {type(value)}\n{json.dumps(value, indent=2)}")
        gnmi_set = proto.gnmi_pb2.Update()
        gnmi_set.path.CopyFrom(
            gnmi_util.GnmiMessageConstructor.parse_xpath_to_gnmi_path(path)
        )
        if encoding.lower() == "json_ietf":
            gnmi_set.val.json_ietf_val = json.dumps(value).encode("utf-8")
        else:
            raise ValueError(f"gNMI encoding {encoding} not supported yet.")
        return gnmi_set

    def _gnmi_set_update(self, request, updates, encoding):
        try:
            updates_json = json_duplicate_keys.loads(updates)
        except Exception as exc:
            raise ValueError("gNMI set: Invalid updates JSON string.") from exc
        for path, value in updates_json.items():
            path = path.split("{{{")[0]
            if not value:
                continue
            request.update.append(self._proto_encode(path, value, encoding))
        return request

    def _gnmi_set_replace(self, request, replaces, encoding):
        try:
            replaces_json = json_duplicate_keys.loads(replaces)
        except Exception as exc:
            raise ValueError("gNMI set: Invalid replaces JSON string.") from exc
        for path, value in replaces_json.items():
            if not value:
                continue
            request.replace.append(self._proto_encode(path, value, encoding))
        return request

    @keyword("gNMI set")
    def gnmi_set(
        self,
        device: str,
        updates: str | None = None,
        replaces: str | None = None,
        deletes: list | None = None,
        encoding: str = "JSON_IETF",
    ):
        """
        gNMI set

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: updates: (list) list of path/value json strings
            :param: replaces: (list) list of path/value json strings
            :param: deletes: (list) list of paths json strings
            :param: encoding: (str) one of JSON, JSON_IETF, PROTO
        :Returns:
            :returns: (bool) True if applied successfully
        :Raises:
            :raises: GnmiException if gNMI set failed

        :Example:

            .. code:: robotframework

                gNMI set    ${device}    updates=${rpc1}    replaces=${rpc2}    deletes=${rpc3}

        """
        logger.debug(
            f"gNMI set device: {device} updates: {updates} replaces: {replaces} deletes: {deletes} "
            f"encoding: {encoding}"
        )
        gnmi_session = self._get_gnmi_session(device)
        request = proto.gnmi_pb2.SetRequest()
        if updates is not None:
            request = self._gnmi_set_update(request, updates, encoding)
        if replaces is not None:
            request = self._gnmi_set_replace(request, replaces, encoding)
        if deletes is not None:
            for path in deletes:
                request.delete.append(
                    gnmi_util.GnmiMessageConstructor.parse_xpath_to_gnmi_path(path)
                )

        set_result = gnmi_session.set(request)
        logger.debug(f"\ngNMI.set response: {set_result}")
        return set_result

    @staticmethod
    def _gnmi_subscribe_return_values(response_update):
        """
        Extracts values from a gnmi_pb2.SubscribeResponse object

        :param: (gnmi_pb2.SubscribeResponse) response from subscribe
        :returns: (list) List of values
        """
        values = []
        for item in response_update.update.update:
            item_value = item.val.json_ietf_val
            item_json = json.loads(item_value)
            values.append(item_json)
        return values

    @staticmethod
    def _gnmi_subscribe_return_full_proto_message(raw_data):
        """
        Extracts notifications from a gnmi_pb2.SubscribeResponse object

        :param: (gnmi_pb2.SubscribeResponse) response from subscribe
        :returns: (list) List of dict, full response with context
        """
        resp_json = MessageToDict(raw_data)
        result = resp_json.get("update", None)
        if result:
            updates = result.get("update", [])
            for item in updates:
                if "val" in item:
                    item_value = item["val"].get("jsonIetfVal")
                    if item_value:
                        item_decoded = base64.b64decode(item_value)
                        value_str = item_decoded.decode("utf-8")
                        item["val"] = json.loads(value_str) if value_str else None
                result["update"] = item
        return result

    @keyword("gNMI subscribe")
    def gnmi_subscribe(
        self,
        device: str,
        path: str | None = None,
        mode: str | None = None,
        subscription_mode: str = "SAMPLE",
        encoding: str = "JSON_IETF",
        sample_interval_sec: str | None = None,
        full_response: str = "False",
    ):
        """
        gNMI subscribe

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: path: (str) subscription xpath
            :param: mode: (str) subscription mode one of STREAM, POLL, ONCE
            :param: subscription_mode: (str) one of SAMPLE, TARGET_DEFINED, ON_CHANGE
            :param: encoding: (str) encoding one of PROTO, JSON, JSON_IETF
            :param: sample_interval_sec: (str) interval in seconds
            :param: full_response: (str) True for full proto Message response, False (default) for values only
        :Returns:
            :returns: (list) List of Values if full_response=${FALSE} (default) or list of dict (if full_response=${TRUE})
        :Raises:
            :raises: (GnmiException) if device or testbed details are missing

        :Example:

            .. code:: robotframework

                gNMI subscribe    ${device}    path=${path}    mode=ONCE    encoding=JSON_IETF

        """
        logger.debug(
            f"gNMI subscribe device: {device} path: {path}, mode: {mode}, "
            f"subscription_mode: {subscription_mode} encoding: {encoding} full_response: {full_response}"
        )
        gnmi_session = self._get_gnmi_session(device)

        request = proto.gnmi_pb2.SubscribeRequest()
        subscription_list = proto.gnmi_pb2.SubscriptionList()
        subscription_list.mode = proto.gnmi_pb2.SubscriptionList.Mode.Value(mode)
        subscription_list.encoding = proto.gnmi_pb2.Encoding.Value(encoding)

        sampled_subscription1 = proto.gnmi_pb2.Subscription()
        sampled_subscription1.path.CopyFrom(
            gnmi_util.GnmiMessageConstructor.parse_xpath_to_gnmi_path(path)
        )
        sampled_subscription1.mode = proto.gnmi_pb2.SubscriptionMode.Value(
            subscription_mode
        )
        sampled_subscription1.sample_interval = int(
            float(sample_interval_sec) * int(1e9)
        )
        subscription_list.subscription.extend([sampled_subscription1])
        request.subscribe.CopyFrom(subscription_list)

        def my_gen(data):
            yield data

        response = []
        for index, response_update in enumerate(
            gnmi_session.subscribe(my_gen(request))
        ):
            if response_update.HasField("sync_response"):
                logger.debug(f"BREAK NOW: {response_update.sync_response}")
                break
            logger.info(
                f"-------- index: {index} Len: {len(response_update.update.update)} --------"
            )
            logger.debug(f"subscribe_response_update:\n{response_update}\n")
            if is_falsy(full_response):
                notification_decoded = self._gnmi_subscribe_return_values(
                    response_update
                )
            else:
                notification_decoded = self._gnmi_subscribe_return_full_proto_message(
                    response_update
                )
            response.append(notification_decoded)
        return response

    @staticmethod
    def _execute_gnoi_command(self, command, device, via, timeout):
        username, password, fqdn, port, root_certificate = (
            self._get_gnmi_device_details(device, via)
        )
        cmd = f"gnoic -a {fqdn}:{port} --tls-ca {root_certificate} -u {username} -p {password} system {command}"
        logger.info(f"Executing gNOI cmd: {cmd.replace(password, '***')}")
        try:
            response = subprocess.run(
                cmd.split(" "), capture_output=True, timeout=timeout
            )
            logger.info(f"response.returncode: {response.returncode}")
            logger.info(f"response.stderr: {response.stderr}")
            logger.info(f"response.stdout: {response.stdout}")
            return response
        except Exception as e:
            raise GnmiException(
                f"gNOI {command} on device '{device}' failed, return error:\n{e}"
            )

    @keyword("gNOI ping")
    def gnoi_ping(
        self,
        device: str,
        dest: str,
        via: str = "gnmi",
        source: str | None = None,
        interval: str = "1s",
        count: int = 5,
        size: int = 64,
        timeout: int = 60,
    ):
        """
        gNOI ping

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: dest: (str) destination IpV4 address
            :param: via: (str) optional connection name from testbed.yaml (default is 'gnmi')
            :param: source: (str) source IPv4 address
            :param: interval: (str) ping interval in seconds
            :param: count: (str) ping count
            :param: size: (str) ping packet size
            :param: timeout: (int) timeout in seconds

        :Returns:
            :returns: pkt_received: (int) Number of packets received
        :Raises:
            :raises: (KeyError, AttributeError, GnmiException) if device or testbed details are missing, or ping error (invalid ip or creds)

        :Example:

            .. code:: robotframework

                gNOI ping    ${device}    dest=10.11.0.2    source=10.11.0.2    count=5

        """
        if source:
            arg_source = f"--source {source} "
        else:
            arg_source = ""
        cmd = f"ping --destination {dest} {arg_source}--protocol v4 --interval {interval} --count {count} --size {size}"
        result = self._execute_gnoi_command(self, cmd, device, via, timeout)
        match = re.search(rb"(\d+) packets received", result.stdout)
        if match:
            pkt_received = match.groups()[0]
            return pkt_received
        raise GnmiException(
            f"gNOI Ping on device '{device}' source {source} to {dest} size {size} failed,"
            f" return error:\n{result.stderr}"
        )

    @keyword("gNOI traceroute ")
    def gnoi_traceroute(
        self,
        device: str,
        dest: str,
        via: str = "gnmi",
        source: str = None,
        l3protocol: str = "v4",
        l4protocol: str = "UDP",
        maxttl: int = 64,
        wait: str = "5s",
        timeout: int = 60,
    ):
        """
        gNOI traceroute

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: dest: (str) destination IpV4 address
            :param: via: (str) optional connection name from testbed.yaml (default is 'gnmi')
            :param: source: (str) source IpV4 address
            :param: l3protocol: (str) one of v4, v6
            :param: l4protocol: (str) UDP (ICMP, TCP not implemented)
            :param: maxttl: (int) Max TTL
            :param: wait: (str) duration of wait until response
            :param: timeout: (int) timeout in seconds

        :Returns:
            :returns: traceroute: (str) Raw traceroute output
        :Raises:
            :raises: (KeyError, AttributeError, GnmiException) if device or testbed details are missing, or traceroute error (invalid ip or creds)

        :Example:

            .. code:: robotframework

                gNOI traceroute    PE1    dest=10.0.0.99    source=10.11.0.2

        """
        if source:
            arg_source = f"--source {source} "
        else:
            arg_source = ""
        cmd = (
            f"traceroute --destination {dest} {arg_source}--l3protocol {l3protocol} --l4protocol {l4protocol} "
            f"--max-ttl {maxttl} --wait {wait} "
        )
        result = self._execute_gnoi_command(self, cmd, device, via, timeout)
        logger.info(
            f"gNOI traceroute {device} dest:{dest}\nResult:\n{result}\n\nstdout:\n{str(result.stdout)}"
        )
        if result.returncode != 0:
            raise GnmiException(
                f"gNOI Traceroute on device '{device}' to {dest} failed, error:\n{result.stderr}"
            )
        return result.stdout

    @keyword("gNOI system time")
    def gnoi_system_time(self, device: str, via: str = "gnmi", timeout: int = 600):
        """
        gNOI system time

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: via: (str) optional connection name from testbed.yaml (default is 'gnmi')
        :Returns:
            :returns: (tuple) tuple (device_fqdn: string, timestamp ISO: string, Linux timestamp epoch: integer)
        :Raises:
            :raises: (KeyError, AttributeError) if device or testbed details are missing.

        :Example:

            .. code:: robotframework

                gNOI system time    ${device}

        """
        cmd = "time"
        result = self._execute_gnoi_command(self, cmd, device, via, timeout)
        m = re.search(
            rb"\| (\S+:\d+) \|\ ([\d-]+\s[\d:.]+\s[+-]?\d+\s\w+) \|\ (\d+) *\|",
            result.stdout,
        )
        if not m:
            raise ValueError(
                f"gNOI system time '{device}' failed to extract details from output: {result.stdout}"
            )
        return m.groups()[0], m.groups()[1], int(m.groups()[2])

    @keyword("gNOI reboot")
    def gnoi_reboot(self, device: str, via: str = "gnmi", timeout: int = 600):
        """
        gNOI reboot

        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: via: (str) optional connection name from testbed.yaml (default is 'gnmi')
            :param: timeout: (int) timeout in seconds
        :Returns:
            :returns: (bool) True if reboot triggered successfully

        :Example:

            .. code:: robotframework

                gNOI reboot    ${device}

        """
        cmd = "reboot"
        result = self._execute_gnoi_command(self, cmd, device, via, timeout)
        return not result.returncode

    @keyword("gRPC action")
    def grpc_action(self, device: str, data: str, timeout: int = 30):
        """
        Execute gRPC action on a given protocol buffer, with provided parameters


        :Parameters:
            :param: device: (str) device name as defined in testbed.yaml
            :param: data: (str) gRPC action parameters
        :Returns:
            :returns: (None type) None
        :Raises:
            :raises: (GnmiException) if gRPC action returns an error
        :Example:

            .. code:: robotframework

                # Examples for password-encryption Master Key creation or update:

                gNMI connect to device    ${device}
                ${resp}=   gRPC action
                ...    device=${device}
                ...    data={"Cisco-IOS-XR-lib-keychain-act:master-key-add":{"new-key":"%ENV(MASTER_KEY)"}}

                # Or for a key update:
                gNMI connect to device    ${device}
                ${resp}=   gRPC action
                ...    device=${device}
                ...    data={"Cisco-IOS-XR-lib-keychain-act:master-key-update":{"old-key": "%ENV(OLD_KEY)","new-key":"%ENV(NEW_KEY)"}}

                # Or Master key deletion:
                gNMI connect to device    ${device}
                ${resp}=   gRPC action    ${device}    {"Cisco-IOS-XR-lib-keychain-act:master-key-delete":{}}

        """
        # in data field, swap Environment Variables names to their values, if any
        data = re.sub(r"%ENV\((.*?)\)", lambda m: os.environ.get(m.group(1), ""), data)

        gnmi_session = self._get_gnmi_session(device)
        stub = ems_grpc_pb2_grpc.gRPCExecStub(gnmi_session.channel)
        req_id = randint(10000, 30000)
        logger.debug(f"Randomly generated reqId: {req_id}")
        responses = stub.ActionJSON(
            ems_grpc_pb2.ActionJSONArgs(ReqId=req_id, yangpathjson=data),
            timeout=timeout,
        )
        for item, response in enumerate(responses):
            if response.errors != "":
                raise GnmiException(
                    f"gRPC action on {device} response {item}: {response.errors}"
                )
        logger.debug(f"Response: {responses.code()}")
        logger.debug(f"Response code name: {responses.code().name}")
        logger.info("gRPC action completed successfully.")
        return responses.code().name
