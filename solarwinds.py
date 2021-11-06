#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Dalton Rardin
# GNU General Public License v3.0+ (https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

import itertools
import types
from logging import debug

__metaclass__ = type

DOCUMENTATION = r"""
    name: solarwinds
    plugin_type: inventory
    short_description: Returns Ansible inventory from Solarwinds NCM.
    description: Returns Ansible inventory from Solarwinds NCM.
    author:
        - Dalton Rardin (@dalrrard)
    options:
        plugin:
            description: Name of the plugin
            required: true
            choices: ['solarwinds']
        base_url:
            description: Base URL of the Solarwinds NCM server
            required: true
        api_port:
            description: API port of the Solarwinds NCM server
            required: false
            default: 17778
        username:
            description: Solarwinds username (with domain if applicable)
            required: true
        password:
            description: Solarwinds password
            required: true
        verify_ssl:
            description: Verify SSL certificate
            required: false
            type: boolean
            default: true
        additional_properties:
            description: Additional properties to include in the inventory
            required: false
            type: list
    extends_documentation_fragment:
        - constructed
"""

import json
import re
from dataclasses import dataclass, fields, make_dataclass
from functools import cache
from typing import (
    Any,
    AnyStr,
    Iterable,
    Iterator,
    Optional,
    Type,
    TypeVar,
    Union,
    overload,
)

from ansible.errors import AnsibleInternalError, AnsibleOptionsError, AnsibleParserError
from ansible.inventory.data import InventoryData
from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.module_utils.urls import Request
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.inventory import (
    BaseInventoryPlugin,
    Constructable,
    to_safe_group_name,
)
from ansible.utils.display import Display

display = Display()

T = TypeVar("T")


@dataclass
class ConnectionProfileResponse:
    """Model for the connection profile query response from the Solarwinds API."""

    id_: int
    name: str
    user_name: str
    password: str
    enable_level: str
    enable_password: str
    execute_script_protocol: str
    request_config_protocol: str
    transfer_config_protocol: str
    telnet_port: int
    ssh_port: int
    use_for_auto_detect: bool


# @dataclass
# class InventoryResponse:
#     """Model for the inventory query response from the Solarwinds API."""

#     agent_ip: str
#     sys_name: str
#     owner: str
#     mls: str
#     layer: str
#     tier: str
#     priority: str
#     region: str
#     site: str
#     site_code: str = field(init=False)
#     connection_profile: int
#     machine_type: str
#     os_version: str
#     os_image: str
#     connection_profile_details: Optional[ConnectionProfileResponse] = None

#     def __post_init__(self) -> None:
#         """Post-initialization hook for InventoryResponse."""
#         self.site_code = self.site.split("_", maxsplit=1)[0]

#     @classmethod
#     def get_field_names(cls) -> Iterator[str]:
#         field_names = (getattr(field_name, "name") for field_name in fields(cls))

#         return field_names


def get_field_names(cls: object) -> Iterator[str]:
    field_names = (getattr(field_name, "name") for field_name in fields(cls))

    return field_names


class QuerySolarwinds(Iterator[Type[T]]):
    """Query Solarwinds for inventory."""

    def __init__(
        self,
        base_url: str,
        port: Optional[int],
        username: str,
        password: str,
        verify: bool,
        additional_properties: Optional[list[str]] = None,
    ) -> None:
        self.request = Request(
            url_username=str(username),
            url_password=str(password),
            headers={"Content-type": "application/json"},
            validate_certs=verify,
        )
        self.base_url = base_url
        if port is None:
            self.port = 17778
        else:
            self.port = port
        self.url = f"{self.base_url}:{self.port}/SolarWinds/InformationService/v3/Json/"
        # self.inventory_payload = {
        #     "query": (
        #         "SELECT "
        #         "    CN.AgentIP, "
        #         "    CN.SysName, "
        #         "    CN.ConnectionProfile, "
        #         "    CN.MachineType, "
        #         "    CN.OSVersion, "
        #         "    CN.OSImage "
        #         "FROM Cirrus.Nodes CN "
        #         "    WHERE CN.Vendor = 'Cisco' "
        #     )
        # }
        self.inventory_payload = [
            "AgentIP",
            "SysName",
            "ConnectionProfile",
            "MachineType",
            "OSVersion",
            "OSImage",
        ]
        self._initial_inventory: Iterator[Type[T]] = self._query_swis(
            "InventoryResponse", self.inventory_payload
        )
        self._inventory = self._get_connection_profiles()
        if additional_properties is not None:
            self._custom_properties = self._query_swis(
                "CustomProperties", additional_properties
            )
            self._inventory = itertools.chain(self._inventory, self._custom_properties)

    def __next__(self) -> Type[T]:
        return next(self._inventory)

    def __iter__(self) -> Iterator[Type[T]]:
        """Yield InventoryResponse item."""
        for item in self._inventory:
            yield item

    @cache
    def _get_connection_profile(
        self, profile_id: int
    ) -> Optional[ConnectionProfileResponse]:
        """Get connection profile from Solarwinds and store in dataclass."""
        entity = "Cirrus.Nodes"
        swis_action = "Invoke"
        swis_verb = "GetConnectionProfile"
        try:
            response = self.request.post(
                f"{self.url}{swis_action}/{entity}/{swis_verb}",
                data=json.dumps([profile_id]),
            )
        except six.moves.urllib_error.HTTPError as exc:  # pylint: disable=no-member
            raise AnsibleParserError(
                "The server could not fulfill the request.\nReason: %s. %s"
                % (to_native(exc), to_native(exc.read())),
            ) from None
        except six.moves.urllib_error.URLError as exc:  # pylint: disable=no-member
            raise AnsibleParserError(
                "The server could not be reached. Reason: %s." % to_native(exc.reason)
            ) from None
        json_response = json.load(response)
        if json_response:
            return ConnectionProfileResponse(
                **InventoryModule.clean_vars(json_response)
            )
        return None

    def _get_connection_profiles(self) -> Iterator[Type[T]]:
        """Get connection profiles for each InventoryResponse item."""
        self.InventoryResponse.append("connection_profile_details")
        for item in self._initial_inventory:
            profile_id: int = item.connection_profile
            if profile_id:
                profile = self._get_connection_profile(profile_id)
                item.connection_profile_details = profile
                yield item

    def _query_swis(self, cls_name: str, node_fields: list[str]) -> Iterator[Type[T]]:
        """Send request to Solarwinds SWIS using SWQL.

        Pull IP Address, Device Name, Owner, Layer, Site,
        and Vendor then save to json file.
        """
        if node_fields is None:
            raise AnsibleOptionsError("No fields specified.") from None
        _node_fields = set(node_fields)
        _node_fields.add("SysName")
        query_string = ", ".join(f"CN.{field_name}" for field_name in _node_fields)
        payload = {
            "query": (
                "SELECT "
                f"    {query_string} "
                "FROM Cirrus.Nodes CN "
                "    WHERE CN.Vendor = 'Cisco' "
            )
        }
        swis_action = "Query"
        try:
            response = self.request.post(
                f"{self.url}{swis_action}",
                data=json.dumps(payload),
            )
        except six.moves.urllib_error.HTTPError as exc:  # pylint: disable=no-member
            raise AnsibleParserError(
                "The server could not fulfill the request.\nReason: %s. %s"
                % (to_native(exc), to_native(exc.read())),
            ) from None
        except six.moves.urllib_error.URLError as exc:  # pylint: disable=no-member
            raise AnsibleParserError(
                "The server could not be reached. Reason: %s." % to_native(exc.reason)
            ) from None

        try:
            self._json_inventory_response: list[dict[str, Union[str, int]]] = json.load(
                response
            )["results"]
        except KeyError:
            raise AnsibleParserError(
                "Unable to parse JSON response from Solarwinds."
            ) from None

        dynamic_dataclass = self._create_dynamic_dataclass(cls_name, _node_fields)

        return (
            dynamic_dataclass(**result)
            for result in InventoryModule.clean_vars(self._json_inventory_response)
        )

    def _create_dynamic_dataclass(self, cls_name: str, node_fields: set[str]) -> type:
        cleaned_fields = InventoryModule.clean_vars(node_fields)
        dynamic_dataclass = make_dataclass(cls_name, cleaned_fields)
        self.__dict__[cls_name] = cleaned_fields

        return dynamic_dataclass

        # return (
        #     InventoryResponse(**result)
        #     for result in InventoryModule.clean_keys(self._json_inventory_response)
        # )

    # def _get_inventory(self) -> Iterator[InventoryResponse]:
    #     """Send request to Solarwinds SWIS using SWQL.

    #     Pull IP Address, Device Name, Owner, Layer, Site,
    #     and Vendor then save to json file.
    #     """
    #     swis_action = "Query"
    #     try:
    #         response = self.request.post(
    #             f"{self.url}{swis_action}",
    #             data=json.dumps(self.inventory_payload),
    #         )
    #     except six.moves.urllib_error.HTTPError as exc:  # pylint: disable=no-member
    #         raise AnsibleParserError(
    #             "The server could not fulfill the request.\nReason: %s. %s"
    #             % (to_native(exc), to_native(exc.read())),
    #         ) from None
    #     except six.moves.urllib_error.URLError as exc:  # pylint: disable=no-member
    #         raise AnsibleParserError(
    #             "The server could not be reached. Reason: %s." % to_native(exc.reason)
    #         ) from None

    #     try:
    #         self._json_inventory_response: list[dict[str, Union[str, int]]] = json.load(
    #             response
    #         )["results"]
    #     except KeyError:
    #         raise AnsibleParserError(
    #             "Unable to parse JSON response from Solarwinds."
    #         ) from None

    #     return (
    #         InventoryResponse(**result)
    #         for result in InventoryModule.clean_keys(self._json_inventory_response)
    #     )


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "solarwinds"

    def __init__(self) -> None:
        """Initialize InventoryModule."""
        super(InventoryModule, self).__init__()
        self._plugin = ""
        self._base_url = ""
        self._api_port = 17778
        self._username = ""
        self._password = ""
        self._verify_ssl = True

    @staticmethod
    def _fix_builtin_name_overrides(input_string: str) -> str:
        if input_string in six.moves.builtins.__dict__:
            return input_string + "_"
        return input_string

    @staticmethod
    def _to_snake_case(input_string: str) -> str:
        pattern = re.compile(r"((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))")
        substitution = r"_\1"
        return InventoryModule._fix_builtin_name_overrides(
            re.sub(pattern, substitution, input_string).lower()
        )

    @overload
    @staticmethod
    def clean_vars(input_vars: str) -> str:
        ...

    @overload
    @staticmethod
    def clean_vars(input_vars: dict[str, Any]) -> dict[str, Any]:
        ...

    @overload
    @staticmethod
    def clean_vars(input_vars: Iterable[Any]) -> Iterable[Any]:
        ...

    @staticmethod
    def clean_vars(
        input_vars: Union[str, Iterable[Any], dict[str, Any]]
    ) -> Union[str, Iterable[Any], dict[str, Any]]:
        if isinstance(input_vars, str):
            return InventoryModule._to_snake_case(input_vars)
        if isinstance(input_vars, dict):
            return {InventoryModule.clean_vars(k): v for k, v in input_vars.items()}
        if isinstance(input_vars, Iterable):
            if all(isinstance(i, (dict, str)) for i in input_vars):
                return [InventoryModule.clean_vars(i) for i in input_vars]
        raise AnsibleInternalError(
            "clean_vars() was called with an unsupported type: %s"
            % to_native(type(input_vars))
        )

    def verify_file(self, path: AnyStr) -> bool:
        """Verify that this is a valid file to consume."""
        valid = False
        _path: str = to_text(path)
        valid_files = (
            "solarwinds_inventory.yaml",
            "solarwinds_inventory.yml",
            "solarwinds.yaml",
            "solarwinds.yml",
        )
        if super(InventoryModule, self).verify_file(_path):
            if _path.endswith(valid_files):
                valid = True
        return valid

    def _populate(self) -> None:
        """Populate inventory."""
        _raw_inventory = QuerySolarwinds(
            self._base_url,
            self._api_port,
            self._username,
            self._password,
            self._verify_ssl,
            self._additional_properties,
        )

        inventory_fields = _raw_inventory.InventoryResponse
        if self._additional_properties:
            inventory_fields += _raw_inventory.CustomProperties

        for item in _raw_inventory:
            host_name = self.inventory.add_host(item.sys_name)
            if item.__class__.__name__ == "InventoryResponse":
                self.inventory.set_variable(host_name, "ansible_host", item.agent_ip)
                self._set_credentials(item, host_name)
            for field_name in inventory_fields:
                if value := getattr(item, field_name, None):
                    if field_name not in [
                        "node_id",
                        "connection_profile_details",
                        "agent_ip",
                        "sys_name",
                    ]:
                        site_group = self.inventory.add_group(
                            to_safe_group_name("%s_%s" % (field_name, value))
                        )
                        self.inventory.add_child(site_group, host_name)
                        self.inventory.set_variable(host_name, field_name, value)

    def _set_credentials(self, item: "InventoryResponse", host_name: str) -> None:
        if connection_profile := item.connection_profile_details:
            if username := connection_profile.user_name:
                self.inventory.set_variable(
                    host_name,
                    "ansible_user",
                    username,
                )
            if password := connection_profile.password:
                self.inventory.set_variable(
                    host_name,
                    "ansible_password",
                    password,
                )
            if enable_password := connection_profile.enable_password:
                self.inventory.set_variable(
                    host_name,
                    "ansible_become_password",
                    enable_password,
                )

    def parse(
        self,
        inventory: InventoryData,
        loader: DataLoader,
        path: AnyStr,
        cache: bool = False,
    ) -> None:
        """Parse inventory file."""
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        self._sanitize_group_name = InventoryModule.clean_vars
        display.vvv("Reading configuration data from: %s" % to_text(path))
        self._read_config_data(path)
        try:
            self._plugin: str = self.get_option("plugin")
            display.vvv("Found plugin name: %s" % to_text(self._plugin))
            self._base_url: str = self.get_option("base_url")
            display.vvv("Found server url: %s" % to_text(self._base_url))
            self._username: str = self.get_option("username")
            display.vvv("Found username.")
            self._password: str = self.get_option("password")
            display.vvv("Found password.")
        except KeyError as exc:
            raise AnsibleParserError(
                "All options required: %s" % to_native(exc),
                show_content=False,
            ) from None
        self._api_port: int = self.get_option("api_port")
        self._verify_ssl: bool = self.get_option("verify_ssl")
        self._additional_properties: list[str] = self.get_option(
            "additional_properties"
        )
        self._populate()
