"""Catalog of everything this integration knows how to monitor on SFOS.

OIDs come from the Sophos SFOS-FIREWALL-MIB (enterprise 2604.5.1), the
standard IF-MIB / IP-MIB, and HOST-RESOURCES-MIB / UCD-SNMP-MIB for CPU.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Base OIDs
# --------------------------------------------------------------------------
SFOS = "1.3.6.1.4.1.2604.5.1"

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"

# IF-MIB ifTable / ifXTable columns
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_MTU = "1.3.6.1.2.1.2.2.1.4"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
IP_AD_ENT_IF_INDEX = "1.3.6.1.2.1.4.20.1.2"

# CPU sources
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
UCD_SS_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"
CPU_SOURCE_HR = "host_resources"
CPU_SOURCE_UCD = "ucd"

# SFOS IPsec tunnel table entry
VPN_ENTRY = f"{SFOS}.6.1.1.1.1"
VPN_NAME = f"{VPN_ENTRY}.2"
VPN_DESCRIPTION = f"{VPN_ENTRY}.3"
VPN_POLICY = f"{VPN_ENTRY}.4"
VPN_MODE = f"{VPN_ENTRY}.5"
VPN_TYPE = f"{VPN_ENTRY}.6"
VPN_LOCAL_GW = f"{VPN_ENTRY}.7"
VPN_ACTIVE_TUNNELS = f"{VPN_ENTRY}.8"
VPN_STATUS = f"{VPN_ENTRY}.9"
VPN_ACTIVATED = f"{VPN_ENTRY}.10"

# SFOS Wi-Fi AP table entry
AP_ENTRY = f"{SFOS}.7.1.1"
AP_NAME = f"{AP_ENTRY}.1"
AP_MODEL = f"{AP_ENTRY}.2"
AP_IP = f"{AP_ENTRY}.3"
AP_STATUS = f"{AP_ENTRY}.5"
AP_CLIENTS = f"{AP_ENTRY}.6"

# SFOS 22 hardware tree (XGS appliances; absent on most software installs)
HW_FAN_SPEED = f"{SFOS}.9.3.1.2"
HW_PSU_STATUS = f"{SFOS}.9.4.1.2"

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
SERVICE_STATES = {
    0: "untouched",
    1: "stopped",
    2: "initializing",
    3: "running",
    4: "exiting",
    5: "dead",
    6: "frozen",
    7: "unregistered",
}
SUBSCRIPTION_STATES = {
    0: "none",
    1: "evaluating",
    2: "not_subscribed",
    3: "subscribed",
    4: "expired",
    5: "deactivated",
}
HA_STATUS = {0: "disabled", 1: "enabled"}
HA_STATES = {
    0: "not_applicable",
    1: "auxiliary",
    2: "standalone",
    3: "primary",
    4: "faulty",
    5: "ready",
}
HA_LOAD_BALANCING = {0: "not_applicable", 1: "off", 2: "on"}
VPN_STATES = {0: "inactive", 1: "active", 2: "partially_active"}
VPN_TYPES = {1: "host_to_host", 2: "site_to_site", 3: "tunnel_interface"}
IF_OPER_STATES = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}
IF_ADMIN_STATES = {1: "up", 2: "down", 3: "testing"}

# ifType values we skip by default (but still allow selecting)
IF_TYPE_LOOPBACK = 24
IF_TYPE_NAMES = {
    1: "other",
    6: "ethernet",
    23: "ppp",
    24: "loopback",
    53: "virtual",
    131: "tunnel",
    135: "vlan",
    136: "vlan",
    161: "lag",
    209: "bridge",
}


# --------------------------------------------------------------------------
# Item definitions
# --------------------------------------------------------------------------
KIND_NUMBER = "number"  # numeric sensor
KIND_TEXT = "text"  # text sensor
KIND_ENUM = "enum"  # enum sensor (value mapped via options)
KIND_TIMESTAMP = "timestamp"  # derived boot time
KIND_BINARY = "binary"  # binary sensor


@dataclass(frozen=True, slots=True)
class ScalarItem:
    """A single-OID item."""

    key: str
    name: str
    oid: str
    kind: str = KIND_NUMBER
    unit: str | None = None
    device_class: str | None = None
    state_class: str | None = None
    icon: str | None = None
    scale: float = 1.0
    precision: int | None = None
    options: dict[int, str] = field(default_factory=dict)
    diagnostic: bool = False
    default: bool = False
    # Optional attribute OIDs: {attr_name: oid}
    attributes: dict[str, str] = field(default_factory=dict)


def _s(path: str) -> str:
    """SFOS scalar instance OID."""
    return f"{SFOS}.{path}.0"


# ---- System ----
SYSTEM_ITEMS: tuple[ScalarItem, ...] = (
    ScalarItem("cpu_usage", "CPU usage", "", unit="%", state_class="measurement", icon="mdi:cpu-64-bit", precision=1, default=True),
    ScalarItem("memory_usage", "Memory usage", _s("2.5.2"), unit="%", state_class="measurement", icon="mdi:memory", default=True),
    ScalarItem("memory_capacity", "Memory capacity", _s("2.5.1"), unit="MB", device_class="data_size", icon="mdi:memory", diagnostic=True),
    ScalarItem("swap_usage", "Swap usage", _s("2.5.4"), unit="%", state_class="measurement", icon="mdi:swap-horizontal", default=True),
    ScalarItem("swap_capacity", "Swap capacity", _s("2.5.3"), unit="MB", device_class="data_size", icon="mdi:swap-horizontal", diagnostic=True),
    ScalarItem("disk_usage", "Disk usage", _s("2.4.2"), unit="%", state_class="measurement", icon="mdi:harddisk", default=True),
    ScalarItem("disk_capacity", "Disk capacity", _s("2.4.1"), unit="MB", device_class="data_size", icon="mdi:harddisk", diagnostic=True),
    ScalarItem("live_users", "Live users", _s("2.6"), unit="users", state_class="measurement", icon="mdi:account-multiple", default=True),
    ScalarItem("boot_time", "Last boot", _s("2.2"), kind=KIND_TIMESTAMP, device_class="timestamp", icon="mdi:restart", default=True),
    ScalarItem("firmware", "Firmware version", _s("1.3"), kind=KIND_TEXT, icon="mdi:package-variant", diagnostic=True, default=True),
    ScalarItem("device_name", "Device name", _s("1.1"), kind=KIND_TEXT, icon="mdi:label", diagnostic=True),
    ScalarItem("device_model", "Model", _s("1.2"), kind=KIND_TEXT, icon="mdi:server-network", diagnostic=True),
    ScalarItem("serial", "Serial / appliance key", _s("1.4"), kind=KIND_TEXT, icon="mdi:key", diagnostic=True),
    ScalarItem("webcat_version", "Web category version", _s("1.5"), kind=KIND_TEXT, icon="mdi:web", diagnostic=True),
    ScalarItem("ips_version", "IPS pattern version", _s("1.6"), kind=KIND_TEXT, icon="mdi:shield-search", diagnostic=True),
    ScalarItem("http_hits", "HTTP hits", _s("2.7"), unit="hits", state_class="total_increasing", icon="mdi:web"),
    ScalarItem("ftp_hits", "FTP hits", _s("2.8"), unit="hits", state_class="total_increasing", icon="mdi:folder-network"),
    ScalarItem("pop3_hits", "POP3 hits", _s("2.9.1"), unit="hits", state_class="total_increasing", icon="mdi:email"),
    ScalarItem("imap_hits", "IMAP hits", _s("2.9.2"), unit="hits", state_class="total_increasing", icon="mdi:email"),
    ScalarItem("smtp_hits", "SMTP hits", _s("2.9.3"), unit="hits", state_class="total_increasing", icon="mdi:email-fast"),
    ScalarItem("processes", "Running processes", "1.3.6.1.2.1.25.1.6.0", unit="processes", state_class="measurement", icon="mdi:cogs"),
    ScalarItem("load_1", "Load average (1 min)", "1.3.6.1.4.1.2021.10.1.3.1", state_class="measurement", icon="mdi:speedometer", precision=2),
    ScalarItem("load_5", "Load average (5 min)", "1.3.6.1.4.1.2021.10.1.3.2", state_class="measurement", icon="mdi:speedometer", precision=2),
    ScalarItem("load_15", "Load average (15 min)", "1.3.6.1.4.1.2021.10.1.3.3", state_class="measurement", icon="mdi:speedometer", precision=2),
)

# ---- Services (SFOS ServiceStatsType) ----
_SERVICES = (
    (1, "pop3", "POP3 service"),
    (2, "imap4", "IMAP4 service"),
    (3, "smtp", "SMTP service"),
    (4, "ftp", "FTP service"),
    (5, "http", "HTTP proxy service"),
    (6, "antivirus", "Anti-virus service"),
    (7, "antispam", "Anti-spam service"),
    (8, "dns", "DNS service"),
    (9, "ha", "High availability service"),
    (10, "ips", "IPS service"),
    (11, "apache", "Web admin (Apache) service"),
    (12, "ntp", "NTP service"),
    (13, "tomcat", "Tomcat service"),
    (14, "sslvpn", "SSL VPN service"),
    (15, "ipsec", "IPsec VPN service"),
    (16, "database", "Database service"),
    (17, "network", "Network service"),
    (18, "garner", "Logging (Garner) service"),
    (19, "drouting", "Dynamic routing service"),
    (20, "sshd", "SSH service"),
    (21, "dgd", "Gateway monitor (DGD) service"),
)
SERVICE_ITEMS: tuple[ScalarItem, ...] = tuple(
    ScalarItem(key, name, _s(f"3.{idx}"), kind=KIND_ENUM, device_class="enum", icon="mdi:cog-play", options=SERVICE_STATES)
    for idx, key, name in _SERVICES
)

# ---- Licenses ----
_LICENSES = (
    (1, "base_firewall", "Base firewall license"),
    (2, "network_protection", "Network protection license"),
    (3, "web_protection", "Web protection license"),
    (4, "email_protection", "Email protection license"),
    (5, "webserver_protection", "Web server protection license"),
    (6, "sandstorm", "Zero-day protection (Sandstorm) license"),
    (7, "enhanced_support", "Enhanced support license"),
    (8, "enhanced_plus_support", "Enhanced Plus support license"),
    (9, "central_orchestration", "Central orchestration license"),
)
LICENSE_ITEMS: tuple[ScalarItem, ...] = tuple(
    ScalarItem(
        key,
        name,
        _s(f"5.{idx}.1"),
        kind=KIND_ENUM,
        device_class="enum",
        icon="mdi:certificate",
        options=SUBSCRIPTION_STATES,
        attributes={"expiry_date": _s(f"5.{idx}.2")},
    )
    for idx, key, name in _LICENSES
)

# ---- High availability ----
HA_ITEMS: tuple[ScalarItem, ...] = (
    ScalarItem("ha_status", "HA status", _s("4.1"), kind=KIND_ENUM, device_class="enum", icon="mdi:server-network", options=HA_STATUS),
    ScalarItem("ha_state", "HA state (this device)", _s("4.4"), kind=KIND_ENUM, device_class="enum", icon="mdi:server", options=HA_STATES),
    ScalarItem("ha_peer_state", "HA state (peer)", _s("4.5"), kind=KIND_ENUM, device_class="enum", icon="mdi:server-outline", options=HA_STATES),
    ScalarItem("ha_load_balancing", "HA load balancing", _s("4.7"), kind=KIND_ENUM, device_class="enum", icon="mdi:scale-balance", options=HA_LOAD_BALANCING),
    ScalarItem("ha_config_mode", "HA mode", _s("4.6"), kind=KIND_TEXT, icon="mdi:server-network", diagnostic=True),
    ScalarItem("ha_peer_ip", "HA peer IP", _s("4.10"), kind=KIND_TEXT, icon="mdi:ip-network", diagnostic=True),
)

# ---- Hardware (SFOS 22+, XGS) ----
HARDWARE_ITEMS: tuple[ScalarItem, ...] = (
    ScalarItem("cpu_temperature", "CPU temperature", _s("9.2"), unit="°C", device_class="temperature", state_class="measurement", scale=0.1, precision=1),
    ScalarItem("npu_temperature", "NPU temperature", _s("9.1"), unit="°C", device_class="temperature", state_class="measurement", scale=0.1, precision=1),
)

SCALAR_CATALOG: dict[str, dict[str, ScalarItem]] = {
    "system": {i.key: i for i in SYSTEM_ITEMS},
    "services": {i.key: i for i in SERVICE_ITEMS},
    "licenses": {i.key: i for i in LICENSE_ITEMS},
    "ha": {i.key: i for i in HA_ITEMS},
    "hardware": {i.key: i for i in HARDWARE_ITEMS},
}


# ---- Per-interface metrics ----
@dataclass(frozen=True, slots=True)
class MetricDef:
    """A metric that exists once per table row (interface, tunnel, AP)."""

    key: str
    name: str
    kind: str = KIND_NUMBER
    unit: str | None = None
    device_class: str | None = None
    state_class: str | None = None
    icon: str | None = None
    precision: int | None = None
    options: dict[int, str] = field(default_factory=dict)
    diagnostic: bool = False
    default: bool = False


INTERFACE_METRICS: dict[str, MetricDef] = {
    m.key: m
    for m in (
        MetricDef("status", "Link", kind=KIND_BINARY, device_class="connectivity", default=True),
        MetricDef("rx_rate", "Download rate", unit="Mbit/s", device_class="data_rate", state_class="measurement", icon="mdi:download-network", precision=2, default=True),
        MetricDef("tx_rate", "Upload rate", unit="Mbit/s", device_class="data_rate", state_class="measurement", icon="mdi:upload-network", precision=2, default=True),
        MetricDef("rx_utilization", "Download utilization", unit="%", state_class="measurement", icon="mdi:gauge", precision=1),
        MetricDef("tx_utilization", "Upload utilization", unit="%", state_class="measurement", icon="mdi:gauge", precision=1),
        MetricDef("rx_total", "Data received", unit="GB", device_class="data_size", state_class="total_increasing", icon="mdi:download", precision=3),
        MetricDef("tx_total", "Data sent", unit="GB", device_class="data_size", state_class="total_increasing", icon="mdi:upload", precision=3),
        MetricDef("rx_errors", "Receive errors", unit="errors", state_class="total_increasing", icon="mdi:alert-circle-outline"),
        MetricDef("tx_errors", "Transmit errors", unit="errors", state_class="total_increasing", icon="mdi:alert-circle-outline"),
        MetricDef("rx_discards", "Receive discards", unit="packets", state_class="total_increasing", icon="mdi:delete-outline"),
        MetricDef("tx_discards", "Transmit discards", unit="packets", state_class="total_increasing", icon="mdi:delete-outline"),
        MetricDef("speed", "Link speed", unit="Mbit/s", device_class="data_rate", icon="mdi:speedometer", diagnostic=True),
        MetricDef("ip_address", "IP address", kind=KIND_TEXT, icon="mdi:ip-network"),
    )
}

VPN_METRICS: dict[str, MetricDef] = {
    m.key: m
    for m in (
        MetricDef("connected", "Connected", kind=KIND_BINARY, device_class="connectivity", default=True),
        MetricDef("status", "Status", kind=KIND_ENUM, device_class="enum", icon="mdi:vpn", options=VPN_STATES),
        MetricDef("active_tunnels", "Active tunnels", unit="tunnels", state_class="measurement", icon="mdi:tunnel"),
    )
}

AP_METRICS: dict[str, MetricDef] = {
    m.key: m
    for m in (
        MetricDef("connected", "Connected", kind=KIND_BINARY, device_class="connectivity", default=True),
        MetricDef("clients", "Clients", unit="clients", state_class="measurement", icon="mdi:account-multiple", default=True),
    )
}
