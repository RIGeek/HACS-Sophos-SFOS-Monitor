"""Discovery and polling logic for Sophos SFOS over SNMP.

This module has no Home Assistant dependencies so it can be exercised
directly against a real firewall or an SNMP simulator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import logging
import re
import time
from typing import Any

from . import catalog as cat
from .const import (
    CUSTOM_MODE,
    CUSTOM_MODE_NUMBER,
    CUSTOM_MODE_RATE,
    CUSTOM_MODE_TEXT,
    CUSTOM_OID,
    CUSTOM_SCALE,
    INDEX_REFRESH_SECONDS,
)
from .snmp import SnmpClient, SnmpError, normalize_oid

_LOGGER = logging.getLogger(__name__)

SEP = "|"


def item_id(*parts: str) -> str:
    """Build a data/entity key, e.g. if|Port2|rx_rate."""
    return SEP.join(parts)


def to_number(value: Any) -> float | None:
    """Best-effort numeric conversion (handles strings like '0.15')."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        match = re.search(r"-?\d+(?:\.\d+)?", value)
        if match:
            return float(match.group(0))
    return None


_DATE_FORMATS = (
    "%b %d %Y",
    "%b %d, %Y",
    "%d %b %Y",
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%m/%d/%Y",
    "%d-%m-%Y",
    "%a %b %d %H:%M:%S %Y",
)


def parse_expiry(text: Any) -> datetime | None:
    """Parse the SFOS license expiry string. Returns None if unknown."""
    if not isinstance(text, str) or not text.strip():
        return None
    cleaned = re.sub(r"\s+", " ", text.strip())
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------
@dataclass(slots=True)
class InterfaceInfo:
    """A discovered interface."""

    key: str
    index: str
    name: str
    descr: str
    alias: str
    if_type: int | None
    oper: str
    admin: str
    speed_mbps: float | None
    mac: str | None = None

    @property
    def label(self) -> str:
        """Human label for the settings dialog."""
        extra = []
        if self.alias and self.alias != self.name:
            extra.append(self.alias)
        if self.descr and self.descr not in (self.name, self.alias):
            extra.append(self.descr)
        type_name = cat.IF_TYPE_NAMES.get(self.if_type or 0)
        tail = f" [{self.oper}"
        if type_name:
            tail += f", {type_name}"
        if self.speed_mbps:
            tail += f", {self.speed_mbps:g} Mbit/s"
        tail += "]"
        return f"{self.name}{' — ' + ' / '.join(extra) if extra else ''}{tail}"


@dataclass(slots=True)
class TableRow:
    """A discovered VPN tunnel, AP, fan or PSU."""

    key: str
    index: str
    name: str
    detail: str = ""

    @property
    def label(self) -> str:
        """Human label for the settings dialog."""
        return f"{self.name} [{self.detail}]" if self.detail else self.name


@dataclass(slots=True)
class Discovery:
    """What the firewall answered to."""

    device: dict[str, Any] = field(default_factory=dict)
    scalars: dict[str, set[str]] = field(default_factory=dict)  # category -> keys
    scalar_values: dict[str, Any] = field(default_factory=dict)  # "cat|key" -> raw value
    cpu_source: str | None = None
    hc_counters: bool = False
    interfaces: dict[str, InterfaceInfo] = field(default_factory=dict)
    vpn_tunnels: dict[str, TableRow] = field(default_factory=dict)
    access_points: dict[str, TableRow] = field(default_factory=dict)
    fans: dict[str, TableRow] = field(default_factory=dict)
    psus: dict[str, TableRow] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Serializable summary (for diagnostics)."""
        return {
            "device": self.device,
            "scalars": {k: sorted(v) for k, v in self.scalars.items()},
            "cpu_source": self.cpu_source,
            "hc_counters": self.hc_counters,
            "interfaces": {k: v.label for k, v in self.interfaces.items()},
            "vpn_tunnels": {k: v.label for k, v in self.vpn_tunnels.items()},
            "access_points": {k: v.label for k, v in self.access_points.items()},
            "fans": sorted(self.fans),
            "psus": sorted(self.psus),
        }


@dataclass(slots=True)
class Selection:
    """What the user chose to monitor."""

    scalars: dict[str, list[str]] = field(default_factory=dict)  # category -> keys
    interfaces: list[str] = field(default_factory=list)
    interface_metrics: list[str] = field(default_factory=list)
    vpn_tunnels: list[str] = field(default_factory=list)
    vpn_metrics: list[str] = field(default_factory=list)
    access_points: list[str] = field(default_factory=list)
    fans: list[str] = field(default_factory=list)
    psus: list[str] = field(default_factory=list)
    custom: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ItemValue:
    """One polled value plus optional attributes."""

    value: Any
    attributes: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Monitor
# --------------------------------------------------------------------------
class SfosMonitor:
    """Discovers and polls one SFOS firewall."""

    def __init__(self, client: SnmpClient) -> None:
        self.client = client
        self._counters: dict[str, tuple[float, float]] = {}  # key -> (value, ts)
        self._if_index: dict[str, str] = {}
        self._if_index_ts: float = 0.0
        self._if_hc: bool | None = None
        self._boot_time: datetime | None = None

    # ---------------- discovery ----------------
    async def device_info(self) -> dict[str, Any]:
        """Fetch identity info. Raises SnmpError if the agent doesn't answer."""
        oids = {
            "sys_descr": cat.SYS_DESCR,
            "sys_name": cat.SYS_NAME,
            "sys_object_id": cat.SYS_OBJECT_ID,
            "name": cat.SCALAR_CATALOG["system"]["device_name"].oid,
            "model": cat.SCALAR_CATALOG["system"]["device_model"].oid,
            "firmware": cat.SCALAR_CATALOG["system"]["firmware"].oid,
            "serial": cat.SCALAR_CATALOG["system"]["serial"].oid,
        }
        values = await self.client.get(oids.values())
        info = {key: values.get(normalize_oid(oid)) for key, oid in oids.items()}
        info["is_sfos"] = any(info[k] for k in ("model", "firmware", "serial"))
        return info

    async def discover(self) -> Discovery:
        """Probe everything the catalog knows about."""
        disc = Discovery()
        disc.device = await self.device_info()

        # Scalars
        oid_map: dict[str, tuple[str, str]] = {}
        for category, items in cat.SCALAR_CATALOG.items():
            for item in items.values():
                if item.oid:
                    oid_map[normalize_oid(item.oid)] = (category, item.key)
        values = await self.client.get(oid_map.keys())
        for oid, (category, key) in oid_map.items():
            value = values.get(oid)
            if value is not None and value != "":
                disc.scalars.setdefault(category, set()).add(key)
                disc.scalar_values[item_id(category, key)] = value

        # CPU
        try:
            hr = await self.client.walk(cat.HR_PROCESSOR_LOAD)
        except Exception:  # noqa: BLE001 - optional MIB
            hr = {}
        if hr:
            disc.cpu_source = cat.CPU_SOURCE_HR
        else:
            idle = (await self.client.get([cat.UCD_SS_CPU_IDLE])).get(cat.UCD_SS_CPU_IDLE)
            if idle is not None:
                disc.cpu_source = cat.CPU_SOURCE_UCD
        if disc.cpu_source:
            disc.scalars.setdefault("system", set()).add("cpu_usage")

        # Interfaces
        disc.interfaces, disc.hc_counters = await self._discover_interfaces()

        # IPsec tunnels
        names = await self._safe_walk_column(cat.VPN_NAME)
        statuses = await self._safe_walk_column(cat.VPN_STATUS) if names else {}
        for index, name in names.items():
            if not name:
                continue
            key = str(name)
            state = cat.VPN_STATES.get(statuses.get(index), "unknown")
            disc.vpn_tunnels[key] = TableRow(key, index, key, state)

        # Wi-Fi access points
        ap_names = await self._safe_walk_column(cat.AP_NAME)
        ap_models = await self._safe_walk_column(cat.AP_MODEL) if ap_names else {}
        for index, name in ap_names.items():
            key = str(name or index)
            disc.access_points[key] = TableRow(key, index, key, str(ap_models.get(index) or ""))

        # Hardware tables (XGS / SFOS 22+)
        for index, rpm in (await self._safe_walk_column(cat.HW_FAN_SPEED)).items():
            disc.fans[index] = TableRow(index, index, f"Fan {index}", f"{rpm} RPM")
        for index, state in (await self._safe_walk_column(cat.HW_PSU_STATUS)).items():
            disc.psus[index] = TableRow(index, index, f"Power supply {index}", "up" if to_number(state) == 1 else "down")

        return disc

    async def _safe_walk_column(self, oid: str) -> dict[str, Any]:
        try:
            return await self.client.walk_column(oid)
        except Exception as err:  # noqa: BLE001 - optional tables
            _LOGGER.debug("Walk of %s failed: %s", oid, err)
            return {}

    async def _discover_interfaces(self) -> tuple[dict[str, InterfaceInfo], bool]:
        descr = await self._safe_walk_column(cat.IF_DESCR)
        if not descr:
            return {}, False
        names = await self._safe_walk_column(cat.IF_NAME)
        aliases = await self._safe_walk_column(cat.IF_ALIAS)
        types = await self._safe_walk_column(cat.IF_TYPE)
        oper = await self._safe_walk_column(cat.IF_OPER_STATUS)
        admin = await self._safe_walk_column(cat.IF_ADMIN_STATUS)
        high = await self._safe_walk_column(cat.IF_HIGH_SPEED)
        speed = await self._safe_walk_column(cat.IF_SPEED) if not high else {}
        macs = await self._safe_walk_column(cat.IF_PHYS_ADDRESS)
        hc = bool(await self._safe_walk_column(cat.IF_HC_IN_OCTETS))

        result: dict[str, InterfaceInfo] = {}
        seen: dict[str, int] = {}
        for index, d in descr.items():
            name = str(names.get(index) or d or f"if{index}")
            seen[name] = seen.get(name, 0) + 1
        for index, d in sorted(descr.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
            name = str(names.get(index) or d or f"if{index}")
            key = name if seen[name] == 1 else f"{name}#{index}"
            if index in high:
                spd = to_number(high.get(index))
            else:
                raw = to_number(speed.get(index))
                spd = raw / 1_000_000 if raw else None
            result[key] = InterfaceInfo(
                key=key,
                index=index,
                name=name,
                descr=str(d or ""),
                alias=str(aliases.get(index) or ""),
                if_type=int(types[index]) if isinstance(types.get(index), int) else None,
                oper=cat.IF_OPER_STATES.get(oper.get(index), "unknown"),
                admin=cat.IF_ADMIN_STATES.get(admin.get(index), "unknown"),
                speed_mbps=spd or None,
                mac=str(macs.get(index)) if macs.get(index) else None,
            )
        return result, hc

    # ---------------- polling ----------------
    async def poll(self, sel: Selection) -> dict[str, ItemValue]:
        """Poll everything selected. Raises SnmpError on total failure."""
        data: dict[str, ItemValue] = {}
        now = time.monotonic()

        # -- scalars (+ license expiry attributes) --
        wanted: dict[str, tuple[str, cat.ScalarItem]] = {}
        attr_oids: dict[str, tuple[str, str]] = {}
        for category, keys in sel.scalars.items():
            items = cat.SCALAR_CATALOG.get(category, {})
            for key in keys:
                item = items.get(key)
                if item is None or not item.oid:
                    continue
                wanted[normalize_oid(item.oid)] = (category, item)
                for attr, oid in item.attributes.items():
                    attr_oids[normalize_oid(oid)] = (item_id(category, key), attr)
        # Always fetch uptime so availability is detected even with an empty selection
        get_oids = list(wanted) + list(attr_oids) + [cat.SYS_UPTIME]
        values = await self.client.get(get_oids)
        if all(values.get(o) is None for o in get_oids):
            # Nothing answered at all: treat as a failed poll
            raise SnmpError("Agent returned no data")

        for oid, (category, item) in wanted.items():
            data[item_id(category, item.key)] = ItemValue(self._convert_scalar(item, values.get(oid)))
        for oid, (key, attr) in attr_oids.items():
            if key in data:
                raw = values.get(oid)
                data[key].attributes[attr] = raw
                expiry = parse_expiry(raw)
                if expiry:
                    data[key].attributes["days_remaining"] = (expiry - datetime.now(UTC)).days

        # -- CPU --
        if "cpu_usage" in sel.scalars.get("system", []):
            data[item_id("system", "cpu_usage")] = await self._poll_cpu()

        # -- interfaces --
        if sel.interfaces and sel.interface_metrics:
            data.update(await self._poll_interfaces(sel, now))

        # -- VPN tunnels --
        if sel.vpn_tunnels and sel.vpn_metrics:
            data.update(await self._poll_vpn(sel))

        # -- APs --
        if sel.access_points:
            data.update(await self._poll_aps(sel))

        # -- fans / PSUs --
        hw_oids = {f"{cat.HW_FAN_SPEED}.{i}": item_id("fan", i) for i in sel.fans}
        hw_oids.update({f"{cat.HW_PSU_STATUS}.{i}": item_id("psu", i) for i in sel.psus})
        if hw_oids:
            hw_values = await self.client.get(hw_oids.keys())
            for oid, key in hw_oids.items():
                raw = hw_values.get(normalize_oid(oid))
                if key.startswith("psu"):
                    data[key] = ItemValue(None if raw is None else to_number(raw) == 1)
                else:
                    data[key] = ItemValue(to_number(raw))

        # -- custom OIDs --
        if sel.custom:
            data.update(await self._poll_custom(sel.custom, now))

        return data

    def _convert_scalar(self, item: cat.ScalarItem, raw: Any) -> Any:
        if raw is None:
            return None
        if item.kind == cat.KIND_ENUM:
            num = to_number(raw)
            return item.options.get(int(num)) if num is not None else None
        if item.kind == cat.KIND_TEXT:
            return str(raw)
        if item.kind == cat.KIND_TIMESTAMP:
            ticks = to_number(raw)
            if ticks is None:
                return None
            boot = datetime.now(UTC) - timedelta(seconds=ticks / 100)
            # Keep the previous value unless it moved by more than a minute so the
            # state doesn't jitter every poll.
            if self._boot_time is None or abs((boot - self._boot_time).total_seconds()) > 60:
                self._boot_time = boot.replace(microsecond=0)
            return self._boot_time
        num = to_number(raw)
        if num is None:
            return None
        num *= item.scale
        if item.precision is not None:
            num = round(num, item.precision)
        return int(num) if num.is_integer() and item.precision is None else num

    async def _poll_cpu(self) -> ItemValue:
        hr = await self.client.walk(cat.HR_PROCESSOR_LOAD)
        loads = [n for n in (to_number(v) for v in hr.values()) if n is not None]
        if loads:
            return ItemValue(
                round(sum(loads) / len(loads), 1),
                {"cores": len(loads), "per_core": [int(x) for x in loads], "source": cat.CPU_SOURCE_HR},
            )
        idle = to_number((await self.client.get([cat.UCD_SS_CPU_IDLE])).get(cat.UCD_SS_CPU_IDLE))
        if idle is not None:
            return ItemValue(round(100 - idle, 1), {"source": cat.CPU_SOURCE_UCD})
        return ItemValue(None)

    def _rate(self, key: str, raw: Any, now: float, bits: int) -> float | None:
        """Per-second delta of a counter; handles wraps and resets."""
        value = to_number(raw)
        if value is None:
            self._counters.pop(key, None)
            return None
        prev = self._counters.get(key)
        self._counters[key] = (value, now)
        if prev is None:
            return None
        prev_value, prev_ts = prev
        dt = now - prev_ts
        if dt <= 0:
            return None
        delta = value - prev_value
        if delta < 0:
            if bits == 32 and prev_value > 2**31:
                delta += 2**32
            else:
                return None  # counter reset (reboot)
        return delta / dt

    async def _refresh_if_index(self, force: bool = False) -> None:
        if not force and self._if_index and time.monotonic() - self._if_index_ts < INDEX_REFRESH_SECONDS:
            return
        interfaces, hc = await self._discover_interfaces()
        self._if_index = {k: v.index for k, v in interfaces.items()}
        self._if_hc = hc
        self._if_index_ts = time.monotonic()

    async def _poll_interfaces(self, sel: Selection, now: float) -> dict[str, ItemValue]:
        await self._refresh_if_index(force=any(i not in self._if_index for i in sel.interfaces))
        metrics = set(sel.interface_metrics)
        hc = bool(self._if_hc)
        in_col = cat.IF_HC_IN_OCTETS if hc else cat.IF_IN_OCTETS
        out_col = cat.IF_HC_OUT_OCTETS if hc else cat.IF_OUT_OCTETS
        bits = 64 if hc else 32

        need_in = bool(metrics & {"rx_rate", "rx_total", "rx_utilization"})
        need_out = bool(metrics & {"tx_rate", "tx_total", "tx_utilization"})
        need_speed = bool(metrics & {"speed", "rx_utilization", "tx_utilization"})

        columns: dict[str, str] = {}
        if "status" in metrics:
            columns["oper"] = cat.IF_OPER_STATUS
            columns["admin"] = cat.IF_ADMIN_STATUS
        if need_in:
            columns["in"] = in_col
        if need_out:
            columns["out"] = out_col
        if "rx_errors" in metrics:
            columns["in_err"] = cat.IF_IN_ERRORS
        if "tx_errors" in metrics:
            columns["out_err"] = cat.IF_OUT_ERRORS
        if "rx_discards" in metrics:
            columns["in_disc"] = cat.IF_IN_DISCARDS
        if "tx_discards" in metrics:
            columns["out_disc"] = cat.IF_OUT_DISCARDS
        if need_speed:
            columns["speed"] = cat.IF_HIGH_SPEED

        oid_lookup: dict[str, tuple[str, str]] = {}
        for key in sel.interfaces:
            index = self._if_index.get(key)
            if index is None:
                continue
            for col_name, col in columns.items():
                oid_lookup[f"{col}.{index}"] = (key, col_name)
        values = await self.client.get(oid_lookup.keys()) if oid_lookup else {}
        per_if: dict[str, dict[str, Any]] = {}
        for oid, (key, col_name) in oid_lookup.items():
            per_if.setdefault(key, {})[col_name] = values.get(normalize_oid(oid))

        ip_map: dict[str, list[str]] = {}
        if "ip_address" in metrics:
            for ip, index in (await self._safe_walk_column(cat.IP_AD_ENT_IF_INDEX)).items():
                ip_map.setdefault(str(index), []).append(ip)

        data: dict[str, ItemValue] = {}
        stale = False
        for key in sel.interfaces:
            v = per_if.get(key, {})
            index = self._if_index.get(key)
            if index is None or (columns and all(x is None for x in v.values())):
                stale = True
            speed = to_number(v.get("speed"))
            for metric in sel.interface_metrics:
                k = item_id("if", key, metric)
                if metric == "status":
                    oper = v.get("oper")
                    data[k] = ItemValue(
                        None if oper is None else oper == 1,
                        {
                            "oper_status": cat.IF_OPER_STATES.get(oper, "unknown"),
                            "admin_status": cat.IF_ADMIN_STATES.get(v.get("admin"), "unknown"),
                            "if_index": index,
                        },
                    )
                elif metric in ("rx_rate", "tx_rate", "rx_utilization", "tx_utilization"):
                    direction = "in" if metric.startswith("rx") else "out"
                    # One counter sample per direction per poll, shared by rate + util
                    cache_key = f"_rate_{key}_{direction}"
                    if cache_key not in data:
                        bps = self._rate(f"if|{key}|{direction}", v.get(direction), now, bits)
                        data[cache_key] = ItemValue(None if bps is None else bps * 8)
                    bits_per_s = data[cache_key].value
                    if bits_per_s is None:
                        data[k] = ItemValue(None)
                    elif metric.endswith("rate"):
                        data[k] = ItemValue(round(bits_per_s / 1_000_000, 3))
                    else:
                        data[k] = ItemValue(
                            round(min(100.0, bits_per_s / (speed * 1_000_000) * 100), 1)
                            if speed
                            else None
                        )
                elif metric in ("rx_total", "tx_total"):
                    raw = to_number(v.get("in" if metric == "rx_total" else "out"))
                    data[k] = ItemValue(None if raw is None else round(raw / 1e9, 3))
                elif metric in ("rx_errors", "tx_errors", "rx_discards", "tx_discards"):
                    col = {"rx_errors": "in_err", "tx_errors": "out_err", "rx_discards": "in_disc", "tx_discards": "out_disc"}[metric]
                    raw = to_number(v.get(col))
                    data[k] = ItemValue(None if raw is None else int(raw))
                elif metric == "speed":
                    data[k] = ItemValue(int(speed) if speed is not None else None)
                elif metric == "ip_address":
                    ips = ip_map.get(str(index), [])
                    data[k] = ItemValue(ips[0] if ips else None, {"all_addresses": ips} if len(ips) > 1 else {})
        # drop the internal rate caches
        for cache_key in [k for k in data if k.startswith("_rate_")]:
            data.pop(cache_key)
        if stale:
            self._if_index_ts = 0  # force a re-map next poll
        return data

    async def _poll_vpn(self, sel: Selection) -> dict[str, ItemValue]:
        names = await self._safe_walk_column(cat.VPN_NAME)
        by_name = {str(n): i for i, n in names.items() if n}
        cols = {"status": cat.VPN_STATUS, "active": cat.VPN_ACTIVE_TUNNELS, "activated": cat.VPN_ACTIVATED, "type": cat.VPN_TYPE, "gw": cat.VPN_LOCAL_GW, "policy": cat.VPN_POLICY}
        oid_lookup = {}
        for name in sel.vpn_tunnels:
            index = by_name.get(name)
            if index is not None:
                for c, col in cols.items():
                    oid_lookup[f"{col}.{index}"] = (name, c)
        values = await self.client.get(oid_lookup.keys()) if oid_lookup else {}
        per: dict[str, dict[str, Any]] = {}
        for oid, (name, c) in oid_lookup.items():
            per.setdefault(name, {})[c] = values.get(normalize_oid(oid))
        data: dict[str, ItemValue] = {}
        for name in sel.vpn_tunnels:
            v = per.get(name, {})
            status = v.get("status")
            attrs = {
                "activated": None if v.get("activated") is None else v.get("activated") == 1,
                "connection_type": cat.VPN_TYPES.get(v.get("type")),
                "local_gateway": v.get("gw"),
                "policy": v.get("policy"),
            }
            for metric in sel.vpn_metrics:
                k = item_id("vpn", name, metric)
                if metric == "connected":
                    data[k] = ItemValue(None if status is None else status == 1, attrs)
                elif metric == "status":
                    data[k] = ItemValue(cat.VPN_STATES.get(status) if status is not None else None, attrs)
                elif metric == "active_tunnels":
                    n = to_number(v.get("active"))
                    data[k] = ItemValue(None if n is None else int(n))
        return data

    async def _poll_aps(self, sel: Selection) -> dict[str, ItemValue]:
        names = await self._safe_walk_column(cat.AP_NAME)
        by_name = {str(n or i): i for i, n in names.items()}
        oid_lookup = {}
        for name in sel.access_points:
            index = by_name.get(name)
            if index is not None:
                oid_lookup[f"{cat.AP_STATUS}.{index}"] = (name, "status")
                oid_lookup[f"{cat.AP_CLIENTS}.{index}"] = (name, "clients")
                oid_lookup[f"{cat.AP_IP}.{index}"] = (name, "ip")
        values = await self.client.get(oid_lookup.keys()) if oid_lookup else {}
        per: dict[str, dict[str, Any]] = {}
        for oid, (name, c) in oid_lookup.items():
            per.setdefault(name, {})[c] = values.get(normalize_oid(oid))
        data: dict[str, ItemValue] = {}
        for name in sel.access_points:
            v = per.get(name, {})
            status = v.get("status")
            data[item_id("ap", name, "connected")] = ItemValue(None if status is None else status == 0, {"ip_address": v.get("ip")})
            clients = to_number(v.get("clients"))
            data[item_id("ap", name, "clients")] = ItemValue(None if clients is None else int(clients))
        return data

    async def _poll_custom(self, custom: list[dict[str, Any]], now: float) -> dict[str, ItemValue]:
        oids = {normalize_oid(c[CUSTOM_OID]): c for c in custom}
        values = await self.client.get(oids.keys())
        data: dict[str, ItemValue] = {}
        for oid, conf in oids.items():
            raw = values.get(oid)
            mode = conf.get(CUSTOM_MODE, CUSTOM_MODE_NUMBER)
            scale = float(conf.get(CUSTOM_SCALE) or 1)
            key = item_id("custom", conf["id"])
            if raw is None:
                data[key] = ItemValue(None)
            elif mode == CUSTOM_MODE_TEXT:
                data[key] = ItemValue(str(raw)[:255])
            elif mode == CUSTOM_MODE_RATE:
                rate = self._rate(f"custom|{conf['id']}", raw, now, 64)
                data[key] = ItemValue(None if rate is None else round(rate * scale, 3))
            else:
                num = to_number(raw)
                data[key] = ItemValue(None if num is None else round(num * scale, 4), {"raw": raw})
        return data
