"""Thin async SNMP client around pysnmp 7 (asyncio API).

Everything here works with numeric OIDs only and never loads MIB files, so no
blocking file I/O happens inside the Home Assistant event loop. The one
blocking step (creating the SnmpEngine) is done in an executor by the caller.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import logging
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    next_cmd,
)
from pysnmp.hlapi.v3arch.asyncio import auth as _auth
from pysnmp.proto import rfc1902, rfc1905

from .const import SNMP_V1, SNMP_V2C, SNMP_V3

_LOGGER = logging.getLogger(__name__)

GET_CHUNK = 20  # OIDs per GET PDU; keeps responses well under typical MTU
BULK_REPETITIONS = 25
MAX_WALK_ROWS = 5000

_AUTH_MAP = {
    "none": _auth.usmNoAuthProtocol,
    "md5": _auth.usmHMACMD5AuthProtocol,
    "sha": _auth.usmHMACSHAAuthProtocol,
    "sha224": _auth.usmHMAC128SHA224AuthProtocol,
    "sha256": _auth.usmHMAC192SHA256AuthProtocol,
    "sha384": _auth.usmHMAC256SHA384AuthProtocol,
    "sha512": _auth.usmHMAC384SHA512AuthProtocol,
}
_PRIV_MAP = {
    "none": _auth.usmNoPrivProtocol,
    "des": _auth.usmDESPrivProtocol,
    "3des": _auth.usm3DESEDEPrivProtocol,
    "aes": _auth.usmAesCfb128Protocol,
    "aes192": _auth.usmAesCfb192Protocol,
    "aes256": _auth.usmAesCfb256Protocol,
}


class SnmpError(Exception):
    """Generic SNMP failure (timeout, auth error, unreachable host...)."""


class SnmpTimeout(SnmpError):
    """No response from the agent."""


class SnmpAuthError(SnmpError):
    """The agent rejected our SNMPv3 credentials."""


class SnmpPduError(SnmpError):
    """The agent answered with an error-status (e.g. v1 noSuchName)."""


_AUTH_INDICATIONS = {
    "WrongDigest",
    "UnknownUserName",
    "UnknownSecurityName",
    "DecryptionError",
    "AuthenticationError",
    "AuthenticationFailure",
    "UnsupportedSecurityLevel",
    "UnknownEngineID",
}


@dataclass(slots=True)
class SnmpSettings:
    """Connection settings."""

    host: str
    port: int
    version: str
    community: str | None = None
    username: str | None = None
    auth_protocol: str = "none"
    auth_key: str | None = None
    priv_protocol: str = "none"
    priv_key: str | None = None
    timeout: float = 3
    retries: int = 2


def create_engine() -> SnmpEngine:
    """Create an SnmpEngine. Blocking: run in an executor."""
    return SnmpEngine()


def normalize_oid(oid: str) -> str:
    """Strip whitespace and a leading dot."""
    return oid.strip().lstrip(".")


def is_valid_oid(oid: str) -> bool:
    """Return True for a dotted numeric OID like 1.3.6.1.2.1.1.3.0."""
    parts = normalize_oid(oid).split(".")
    return len(parts) >= 2 and all(p.isdigit() for p in parts)


def convert_value(value: Any) -> Any:
    """Convert a pysnmp value object to a plain Python value.

    Missing objects (noSuchObject / noSuchInstance / endOfMibView) map to None.
    """
    if value is None:
        return None
    if isinstance(value, (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)):
        return None
    if value.__class__.__name__ == "Null":
        return None
    if isinstance(value, rfc1902.IpAddress):
        return ".".join(str(b) for b in value.asOctets())
    if isinstance(value, rfc1902.OctetString):
        raw = value.asOctets()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex(":")
        # Strip NUL padding some agents add and surrounding whitespace.
        return text.replace("\x00", "").strip()
    if isinstance(value, rfc1902.ObjectIdentifier):
        return str(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return value.prettyPrint()


class SnmpClient:
    """Async SNMP client for one agent."""

    def __init__(self, engine: SnmpEngine, settings: SnmpSettings) -> None:
        self._engine = engine
        self.settings = settings
        self._target: UdpTransportTarget | None = None
        self._auth = self._build_auth()
        self._context = ContextData()

    def _build_auth(self) -> CommunityData | UsmUserData:
        s = self.settings
        if s.version == SNMP_V3:
            auth_proto = _AUTH_MAP.get(s.auth_protocol or "none", _auth.usmNoAuthProtocol)
            priv_proto = _PRIV_MAP.get(s.priv_protocol or "none", _auth.usmNoPrivProtocol)
            return UsmUserData(
                s.username or "",
                authKey=s.auth_key if auth_proto is not _auth.usmNoAuthProtocol else None,
                privKey=s.priv_key if priv_proto is not _auth.usmNoPrivProtocol else None,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        mp_model = 0 if s.version == SNMP_V1 else 1
        return CommunityData(s.community or "public", mpModel=mp_model)

    @property
    def uses_bulk(self) -> bool:
        """GETBULK is not part of SNMPv1."""
        return self.settings.version in (SNMP_V2C, SNMP_V3)

    async def _get_target(self) -> UdpTransportTarget:
        if self._target is None:
            try:
                self._target = await UdpTransportTarget.create(
                    (self.settings.host, self.settings.port),
                    timeout=self.settings.timeout,
                    retries=self.settings.retries,
                )
            except Exception as err:  # DNS failure etc.
                raise SnmpError(f"Cannot resolve {self.settings.host}: {err}") from err
        return self._target

    @staticmethod
    def _raise_for_error(error_indication: Any, error_status: Any, error_index: Any) -> None:
        if error_indication:
            text = str(error_indication)
            cls = error_indication.__class__.__name__
            if cls == "RequestTimedOut" or "timeout" in text.lower() or "no snmp response" in text.lower():
                raise SnmpTimeout(text)
            if cls in _AUTH_INDICATIONS:
                raise SnmpAuthError(text)
            raise SnmpError(text)
        if error_status and int(error_status) != 0:
            # noSuchName (2) in v1 is "missing object" rather than a hard failure;
            # the caller handles that by retrying one-by-one.
            status = error_status.prettyPrint() if hasattr(error_status, "prettyPrint") else str(error_status)
            raise SnmpPduError(f"{status} at index {error_index}")

    async def get(self, oids: Iterable[str]) -> dict[str, Any]:
        """GET a list of OIDs. Missing objects are returned as None.

        Requests are chunked. If an agent rejects a whole chunk (SNMPv1
        noSuchName), the chunk is retried OID-by-OID so one bad OID never
        hides the others.
        """
        oid_list = [normalize_oid(o) for o in oids]
        result: dict[str, Any] = {}
        for i in range(0, len(oid_list), GET_CHUNK):
            chunk = oid_list[i : i + GET_CHUNK]
            try:
                result.update(await self._get_chunk(chunk))
            except SnmpPduError:
                if len(chunk) == 1:
                    result[chunk[0]] = None
                    continue
                for oid in chunk:
                    try:
                        result.update(await self._get_chunk([oid]))
                    except SnmpPduError:
                        result[oid] = None
        return result

    async def _get_chunk(self, oids: list[str]) -> dict[str, Any]:
        target = await self._get_target()
        error_indication, error_status, error_index, var_binds = await get_cmd(
            self._engine,
            self._auth,
            target,
            self._context,
            *[ObjectType(ObjectIdentity(oid)) for oid in oids],
            lookupMib=False,
        )
        self._raise_for_error(error_indication, error_status, error_index)
        return {
            normalize_oid(str(name)): convert_value(value) for name, value in var_binds
        }

    async def walk(self, base_oid: str, max_rows: int = MAX_WALK_ROWS) -> dict[str, Any]:
        """Walk a subtree. Returns {full_oid: value} for rows under base_oid."""
        base = normalize_oid(base_oid)
        prefix = base + "."
        rows: dict[str, Any] = {}
        current = base
        target = await self._get_target()
        while len(rows) < max_rows:
            if self.uses_bulk:
                error_indication, error_status, error_index, var_binds = await bulk_cmd(
                    self._engine,
                    self._auth,
                    target,
                    self._context,
                    0,
                    BULK_REPETITIONS,
                    ObjectType(ObjectIdentity(current)),
                    lookupMib=False,
                )
            else:
                error_indication, error_status, error_index, var_binds = await next_cmd(
                    self._engine,
                    self._auth,
                    target,
                    self._context,
                    ObjectType(ObjectIdentity(current)),
                    lookupMib=False,
                )
            if error_status and int(error_status) == 2 and not error_indication:
                break  # v1 noSuchName = end of MIB
            self._raise_for_error(error_indication, error_status, error_index)
            if not var_binds:
                break
            done = False
            last = current
            for name, value in var_binds:  # pysnmp 7: flat tuple of ObjectType
                oid = normalize_oid(str(name))
                if isinstance(value, rfc1905.EndOfMibView) or not oid.startswith(prefix):
                    done = True
                    break
                rows[oid] = convert_value(value)
                last = oid
            if done or last == current:
                break
            current = last
        return rows

    async def walk_column(self, column_oid: str) -> dict[str, Any]:
        """Walk a table column; returns {index_suffix: value}."""
        base = normalize_oid(column_oid)
        rows = await self.walk(base)
        return {oid[len(base) + 1 :]: value for oid, value in rows.items()}

    def close(self) -> None:
        """Release the transport (the engine is owned by the caller)."""
        self._target = None
