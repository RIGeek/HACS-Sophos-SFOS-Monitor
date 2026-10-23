"""Constants for the Sophos SFOS Monitor integration."""

from __future__ import annotations

DOMAIN = "sophos_sfos"
MANUFACTURER = "Sophos"

# ---- Connection (config entry data) ----
CONF_SNMP_VERSION = "snmp_version"
CONF_COMMUNITY = "community"
CONF_AUTH_PROTOCOL = "auth_protocol"
CONF_AUTH_KEY = "auth_key"
CONF_PRIV_PROTOCOL = "priv_protocol"
CONF_PRIV_KEY = "priv_key"
CONF_V3_USERNAME = "v3_username"

SNMP_V1 = "1"
SNMP_V2C = "2c"
SNMP_V3 = "3"
SNMP_VERSIONS = [SNMP_V2C, SNMP_V3, SNMP_V1]

AUTH_NONE = "none"
AUTH_PROTOCOLS = ["none", "md5", "sha", "sha224", "sha256", "sha384", "sha512"]
PRIV_PROTOCOLS = ["none", "des", "3des", "aes", "aes192", "aes256"]

DEFAULT_PORT = 161
DEFAULT_COMMUNITY = "public"

# ---- Options ----
CONF_SCAN_INTERVAL = "scan_interval"
CONF_TIMEOUT = "timeout"
CONF_RETRIES = "retries"

# Selected monitored items (lists of item keys)
CONF_SYSTEM_ITEMS = "system_items"
CONF_SERVICE_ITEMS = "service_items"
CONF_LICENSE_ITEMS = "license_items"
CONF_HA_ITEMS = "ha_items"
CONF_HARDWARE_ITEMS = "hardware_items"
CONF_INTERFACES = "interfaces"
CONF_INTERFACE_METRICS = "interface_metrics"
CONF_VPN_TUNNELS = "vpn_tunnels"
CONF_VPN_METRICS = "vpn_metrics"
CONF_ACCESS_POINTS = "access_points"
CONF_CUSTOM_OIDS = "custom_oids"

DEFAULT_SCAN_INTERVAL = 30
MIN_SCAN_INTERVAL = 5
MAX_SCAN_INTERVAL = 3600
DEFAULT_TIMEOUT = 3
DEFAULT_RETRIES = 2

# How often (seconds) the interface/VPN index maps are refreshed even if
# nothing looks wrong. ifIndex values can shift after a reboot or when
# interfaces are added on SFOS.
INDEX_REFRESH_SECONDS = 600

# Custom OID fields
CUSTOM_NAME = "name"
CUSTOM_OID = "oid"
CUSTOM_UNIT = "unit"
CUSTOM_MODE = "mode"
CUSTOM_SCALE = "scale"
CUSTOM_DEVICE_CLASS = "device_class"
CUSTOM_STATE_CLASS = "state_class"

CUSTOM_MODE_NUMBER = "number"
CUSTOM_MODE_TEXT = "text"
CUSTOM_MODE_RATE = "rate"
CUSTOM_MODES = [CUSTOM_MODE_NUMBER, CUSTOM_MODE_TEXT, CUSTOM_MODE_RATE]
