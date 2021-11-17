#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Dalton Rardin
# GNU General Public License v3.0+ (https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

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

import itertools
import json
import re
from dataclasses import dataclass, make_dataclass
from functools import cache
from typing import (
    TYPE_CHECKING,
    Any,
    AnyStr,
    Generic,
    Iterator,
    MutableMapping,
    Optional,
    Sequence,
    TypeVar,
    Union,
    overload,
)

from ansible.errors import AnsibleInternalError, AnsibleOptionsError, AnsibleParserError
from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.module_utils.urls import Request
from ansible.plugins.inventory import (
    BaseInventoryPlugin,
    Constructable,
    to_safe_group_name,
)
from ansible.utils.display import Display

if TYPE_CHECKING:
    from urllib.request import _UrlopenRet

    from ansible.inventory.data import InventoryData
    from ansible.parsing.dataloader import DataLoader

display = Display()

T = TypeVar("T")  # pylint: disable=invalid-name
DT = TypeVar("DT")  # pylint: disable=invalid-name


class InventoryModule(BaseInventoryPlugin, Constructable, Generic[T]):
    """Main entrypoint for Ansible Inventory Plugin."""

    NAME = "solarwinds"

    def __init__(self) -> None:
        """Initialize InventoryModule and set defaults."""
        super(InventoryModule, self).__init__()
        self._plugin: str = ""
        self._base_url: str = ""
        self._api_port: int = 17778
        self._username: str = ""
        self._password: str = ""
        self._verify_ssl: bool = True
        self._additional_properties: Optional[list[str]] = None

    @staticmethod
    def _fix_builtin_name_overrides(input_string: str) -> str:
        """Append '_' to any string that exactly matches a builtin name.

        Parameters
        ----------
        input_string : str
            The string to check for builtin names.

        Returns
        -------
        str
            The input string with '_' appended to any builtin name.
        """
        if input_string in six.moves.builtins.__dict__:
            return input_string + "_"
        return input_string

    @staticmethod
    def _to_snake_case(input_string: str) -> str:
        """Convert CamelCase and PascalCase to snake_case.

        Convert CamelCase and PascalCase to snake_case then pass the string
        to _fix_builtin_name_overrides to check for builtin names.

        Parameters
        ----------
        input_string : str
            The string to convert.

        Returns
        -------
        str
            The converted string.
        """
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
    def clean_vars(input_vars: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
        ...

    @overload
    @staticmethod
    def clean_vars(
        input_vars: Sequence[MutableMapping[str, Any]]
    ) -> Sequence[MutableMapping[str, Any]]:
        ...

    @overload
    @staticmethod
    def clean_vars(input_vars: Union[set[str], Sequence[str]]) -> Sequence[str]:
        ...

    @staticmethod
    def clean_vars(
        input_vars: Union[
            str,
            set[str],
            Sequence[Union[str, MutableMapping[str, Any]]],
            MutableMapping[str, Any],
        ]
    ) -> Union[
        str, Sequence[Union[str, MutableMapping[str, Any]]], MutableMapping[str, Any]
    ]:
        """Clean inputs to conform to Python naming conventions.

        This method tries to find the important string values in the
        input by recursively type checking and decomposing input_vars
        until it is just a string. It then passes the string to be converted
        to snake case.

        Parameters
        ----------
        input_vars : Union[str, Iterable[Any], MutableMapping[str, Any]]
            Input to be cleaned.

        Returns
        -------
        Union[str, Iterable[Any], MutableMapping[str, Any]]
            Cleaned input.
        """
        if isinstance(input_vars, str):
            return InventoryModule._to_snake_case(input_vars)
        if isinstance(input_vars, MutableMapping):
            return {InventoryModule.clean_vars(k): v for k, v in input_vars.items()}
        if all(isinstance(i, (MutableMapping, str)) for i in input_vars):
            return [InventoryModule.clean_vars(i) for i in input_vars]
        raise AnsibleInternalError(
            "clean_vars() was called with an unsupported type: %s"
            % to_native(type(input_vars))
        )

    def verify_file(self, path: AnyStr) -> bool:
        """Verify that this is a valid file to consume.

        If the file does not exist or does not end with the correct string,
        then Ansible will raise an error.

        Parameters
        ----------
        path : AnyStr
            The path to the file to verify.

        Returns
        -------
        bool
            True if the file is valid, otherwise False.
        """
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
        _raw_inventory: Iterator[T] = QuerySolarwinds(
            self._base_url,
            self._username,
            self._password,
            self._api_port,
            self._additional_properties,
            self._verify_ssl,
        )

        inventory_fields: list[str] = _raw_inventory.InventoryResponse
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

    def _set_credentials(self, item: T, host_name: str) -> None:
        """Set credentials for the hosts in the inventory.

        Parameters
        ----------
        item : T
            The `InventoryResponse` item from Solarwinds.
        host_name : str
            The host name.
        """
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
        inventory: "InventoryData",
        loader: "DataLoader",
        path: AnyStr,
        cache: bool = False,
    ) -> None:
        """Parse the inventory file."""
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
        self._api_port = self.get_option("api_port")
        self._verify_ssl = self.get_option("verify_ssl")
        self._additional_properties = self.get_option("additional_properties")
        self._populate()


@dataclass
class DynamicDT(Generic[DT]):
    pass


@dataclass
class ConnectionProfileResponse:
    """Container for the connection profile query response from the Solarwinds API."""

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


class QuerySolarwinds(Iterator[DT]):
    """Query Solarwinds NCM Cirrus.Nodes for inventory."""

    _sanitize_names = InventoryModule.clean_vars

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        port: int = 17778,
        additional_properties: Optional[list[str]] = None,
        verify: bool = True,
    ) -> None:
        """Set default values and initialize Solarwinds connection.

        Parameters
        ----------
        base_url : str
            Base URL of the Solarwinds NCM server
        username : str
            Solarwinds username (with domain if applicable)
        password : str
            Solarwinds password
        port : int, optional
            API port of the Solarwinds NCM server, by default 17778
        additional_properties : Optional[list[str]], optional
            Additional properties to include in the inventory, by default None
        verify : bool, optional
            Verify TLS/SSL certificate, by default True
        """
        self.request = Request(
            url_username=str(username),
            url_password=str(password),
            headers={"Content-type": "application/json"},
            validate_certs=verify,
        )
        self.base_url = base_url
        self.port = port
        self.url = f"{self.base_url}:{self.port}/SolarWinds/InformationService/v3/Json/"
        self.inventory_payload = [
            "AgentIP",
            "SysName",
            "ConnectionProfile",
            "MachineType",
            "OSVersion",
            "OSImage",
        ]
        self._initial_inventory: Iterator[DT] = self._query_swis(
            "InventoryResponse", self.inventory_payload
        )
        self._inventory = self._get_connection_profiles()
        if additional_properties is not None:
            self._custom_properties: Iterator[DT] = self._query_swis(
                "CustomProperties", additional_properties
            )
            self._inventory = itertools.chain(self._inventory, self._custom_properties)

    def __next__(self) -> DT:
        """Return next item in the iterator."""
        return next(self._inventory)

    def __iter__(self) -> Iterator[DT]:
        """Yield the inventory items.

        This will always yield InventoryResponse items.
        If there are any CustomProperties items, they will be yielded as well.

        Yields
        ------
        Iterator[DT]
            The next item in the iterator.
        """
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
        payload = {"id": profile_id}
        response = self._post_message(payload, swis_action, entity, swis_verb)
        json_response: dict[str, Any] = json.load(response)
        if json_response:
            cleaned_json = QuerySolarwinds._sanitize_names(json_response)
            return ConnectionProfileResponse(**cleaned_json)
        return None

    def _get_connection_profiles(self) -> Iterator[DT]:
        """Get connection profiles for each InventoryResponse item."""
        try:
            self.InventoryResponse.append("connection_profile_details")
        except AttributeError as exc:
            raise AnsibleInternalError(
                "Fatal internal error. QuerySolarwinds has no attribute"
                " InventoryResponse. Exception: %s"
                % to_native(exc)
            ) from None
        for item in self._initial_inventory:
            profile_id: int = item.connection_profile
            if profile_id:
                profile = self._get_connection_profile(profile_id)
                item.connection_profile_details = profile
                yield item

    def _query_swis(self, cls_name: str, node_fields: list[str]) -> Iterator[DT]:
        """Send request to Solarwinds SWIS using SWQL and store response.

        Pass the response to the `_create_dynamic_dataclass` method to create a
        dataclass for the response and then create a generator of instances of
        that dataclass.

        Parameters
        ----------
        cls_name : str
            Name of the dynamic dataclass to use for the response
        node_fields : list[str]
            List of fields to query. SysName will always be included.

        Returns
        -------
        Iterator[DT]
            The next item in the iterator.
        """
        if node_fields is None:
            raise AnsibleOptionsError("No fields specified.") from None

        # Add SysName to the list of fields to query
        # so that we can use it as the hostname later.
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
        response = self._post_message(payload, swis_action)

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
            for result in QuerySolarwinds._sanitize_names(self._json_inventory_response)
        )

    def _build_url(
        self, swis_action: str, entity: Optional[str], swis_verb: Optional[str]
    ) -> str:
        """Build a complete endpoint URL for the Solarwinds API.

        Parameters
        ----------
        swis_action : str
            The action to perform on the Solarwinds API.
        entity : Optional[str], optional
            The entity to perform the action on.
        swis_verb : Optional[str], optional
            The verb to perform the action with.

        Returns
        -------
        str
            The concatenated URL.
        """
        url_builder = [f"{self.url}{swis_action}"]
        if entity is not None:
            url_builder.append(f"{entity}")
            if swis_verb is not None:
                url_builder.append(f"{swis_verb}")
        complete_url = "/".join(url_builder)
        return complete_url

    def _post_message(
        self,
        payload: Union[dict[str, int], dict[str, str]],
        swis_action: str,
        entity: Optional[str] = None,
        swis_verb: Optional[str] = None,
    ) -> "_UrlopenRet":
        """POST a message to Solarwinds using the SWIS API.

        Parameters
        ----------
        payload : Union[dict[str, int], dict[str, str]]
            The payload to POST to the Solarwinds API.
        swis_action : str
            The action to perform on the Solarwinds API.
        entity : Optional[str], optional
            The entity to perform the action on.
        swis_verb : Optional[str], optional
            The verb to perform the action with.

        Returns
        -------
        _UrlopenRet
            The response from the Solarwinds API.
        """
        complete_url = self._build_url(swis_action, entity, swis_verb)
        try:
            response = self.request.post(
                complete_url,
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

        return response

    def _create_dynamic_dataclass(self, cls_name: str, node_fields: set[str]) -> type:
        """Create a dataclass to store the response from Solarwinds in.

        This method also adds the field names to the `QuerySolarwinds.__dict__`
        for later use.

        Parameters
        ----------
        cls_name : str
            Name of the dynamic dataclass to use for the response
        node_fields : set[str]
            List of fields to query. SysName will always be included.

        Returns
        -------
        type
            The dynamic dataclass.
        """
        cleaned_fields = QuerySolarwinds._sanitize_names(node_fields)
        dynamic_dataclass = make_dataclass(
            cls_name, cleaned_fields, bases=(DynamicDT[DT],)
        )
        setattr(self, cls_name, cleaned_fields)

        return dynamic_dataclass
