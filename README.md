# Sophos SFOS Monitor for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz/docs/faq/custom_repositories)
[![Validate](https://github.com/RIGeek/HACS-Sophos-SFOS-Monitor/actions/workflows/validate.yml/badge.svg)](https://github.com/RIGeek/HACS-Sophos-SFOS-Monitor/actions/workflows/validate.yml)
[![Tests](https://github.com/RIGeek/HACS-Sophos-SFOS-Monitor/actions/workflows/tests.yml/badge.svg)](https://github.com/RIGeek/HACS-Sophos-SFOS-Monitor/actions/workflows/tests.yml)

Monitor a **Sophos Firewall (SFOS)** — XGS appliances, virtual or software
installs, including the free Home Edition — from Home Assistant over SNMP.

Because an SFOS box exposes far more than anyone wants as entities, the
integration **discovers what your firewall reports** and gives you a
settings dialog where you tick the items you want and untick the ones you
don't. Unticked items have their entities (and interface devices) removed.

Built and tested against SFOS 22.0 (SFOS-FIREWALL-MIB), it should also work
on SFOS 19–21.

## What it can monitor

| Category | Items | Source |
|---|---|---|
| **System & resources** | CPU usage (with per-core attribute), memory %, swap %, disk %, capacities, live users, last boot, firmware, model, serial, web-category and IPS pattern versions, HTTP/FTP/mail proxy hits, process count, load averages | SFOS MIB, HOST-RESOURCES-MIB, UCD-SNMP-MIB |
| **Services** | 21 SFOS services — DNS, IPS, AV, IPsec, SSL VPN, SSH, web admin, DGD gateway monitor, logging, dynamic routing, NTP, … — each as `running` / `stopped` / `dead` / `untouched` … | SFOS MIB |
| **Licenses** | Base firewall, Network/Web/Email/Web-server protection, Zero-day (Sandstorm), support levels, Central orchestration — status with `expiry_date` and `days_remaining` attributes | SFOS MIB |
| **High availability** | HA status, this/peer HA state, load balancing, mode, peer IP | SFOS MIB |
| **Interfaces** | Per interface (each gets its own device): link up/down, download/upload Mbit/s, download/upload % utilisation, total data in/out (GB, for the Energy-style statistics graphs), errors, discards, link speed, IP address | IF-MIB, IP-MIB |
| **IPsec VPN** | Per connection: connected, status (`active` / `partially_active` / `inactive`), active tunnel count; type, gateway and policy as attributes | SFOS MIB |
| **Wireless APs** | Per Sophos AP: connected, client count | SFOS MIB |
| **Hardware** (XGS on SFOS 22+) | CPU/NPU temperature, fan RPM, power-supply state | SFOS MIB |
| **Custom OIDs** | Anything else the firewall answers to: as a number, text, or a per-second rate from a counter, with your own unit, scale, device class and state class | any |

Throughput is computed from the 64-bit `ifHC*` counters (SNMP v2c/v3), with
correct handling of 32-bit wraps on v1 and of counter resets after a reboot.
Interfaces are tracked by **name** (Port1, Port2.10, …), not by ifIndex, so a
reboot that renumbers interfaces doesn't scramble your entities.

## 1. Enable SNMP on the firewall

1. **Administration › SNMP** — turn on the SNMP agent, then either
   - add a **v1/v2c community** (e.g. `homeassistant`) with *Queries* enabled
     and Home Assistant's IP address as an allowed host, **or**
   - add an **SNMPv3 user** that accepts queries from Home Assistant's IP
     (SHA-256 + AES recommended).
2. **Administration › Device access** — tick **SNMP** for the zone Home
   Assistant lives in (normally **LAN**).
3. Optional check from any Linux box:
   `snmpwalk -v2c -c homeassistant <firewall-ip> 1.3.6.1.4.1.2604.5.1.1`
   should return the device name, model and firmware.

## 2. Install

**HACS (recommended):** HACS › ⋮ › *Custom repositories* › add
`https://github.com/RIGeek/HACS-Sophos-SFOS-Monitor` as an **Integration**,
install **Sophos SFOS Monitor**, then restart Home Assistant.

**Manual:** copy `custom_components/sophos_sfos` into your
`config/custom_components/` folder and restart.

## 3. Add the firewall

*Settings › Devices & services › Add integration › Sophos SFOS Monitor*,
enter the firewall's IP, port (161) and SNMP version, then the community or
v3 credentials. The integration probes the firewall and starts with a
sensible selection:

- CPU, memory, swap, disk, live users, last boot, firmware
- the key services that are running (IPsec, SSL VPN, DNS, IPS, AV, DGD)
- licenses that are subscribed or in evaluation
- every interface that is up (loopback excluded) with link, download and upload rate
- every IPsec connection (connected)
- hardware sensors, if your appliance reports them

## 4. Choose what to monitor (settings dialog)

Open the integration and click **Configure**. A fresh discovery runs and
you get a menu:

- **System & resources / Services / Licenses / High availability /
  Hardware sensors** — tick or untick items. The current value is shown next
  to each one, so you can see e.g. which services are actually running.
- **Interfaces** — pick interfaces *and* which metrics to create for each
  (link, rates, utilisation, totals, errors, discards, speed, IP).
- **IPsec VPN connections / Wireless access points** — pick connections/APs.
- **Add a custom OID** — name, OID, type (number / text / rate), unit,
  scale, device class, state class. The OID is test-read before it's added
  (tick *Add without testing* to skip that).
- **Remove custom OIDs**.
- **Polling & timeouts** — poll interval (default 30 s), SNMP timeout and
  retries.
- **Save and close** — applies everything. Entities for removed items are
  deleted automatically.

Connection settings (IP, version, credentials) can be changed later with
**⋮ › Reconfigure**.

### Custom OID examples

| Name | OID | Type | Unit | Scale |
|---|---|---|---|---|
| WAN download (raw counter → Mbit/s) | `1.3.6.1.2.1.31.1.1.1.6.<ifIndex>` | rate | Mbit/s | `0.000008` |
| TCP connections to the firewall itself | `1.3.6.1.2.1.6.9.0` | number | connections | 1 |
| SNMP uptime (seconds) | `1.3.6.1.2.1.1.3.0` | number | s | `0.01` |

## Notes

- **CPU** comes from HOST-RESOURCES-MIB `hrProcessorLoad` (averaged across
  cores, per-core values as an attribute), falling back to UCD-SNMP
  `ssCpuIdle`. If neither answers, CPU usage isn't offered.
- **Hardware sensors** (temperatures, fans, PSUs) were added to the SFOS MIB
  in v22 and are only reported by XGS hardware; software and virtual installs
  won't show that menu. On SFOS 22.0 GA build 365 these values could be
  returned as strings; the integration parses both.
- **Memory/disk capacity** are reported by SFOS in MB.
- **HA, mail and web-server items** only show up if your firewall reports
  them; on the Home Edition several licenses report `none`/`not_subscribed`
  and mail-related services are `untouched` — that's normal.
- **Diagnostics** (⋮ › Download diagnostics) include a fresh discovery of
  everything the firewall reports, with credentials and serial redacted —
  handy when opening an issue.

## Troubleshooting

| Symptom | Check |
|---|---|
| *No SNMP response* when adding | Device access › SNMP ticked for HA's zone; community/user's allowed host is HA's IP (with Docker/VMs, the host's IP); UDP 161 reachable. |
| *Rejected SNMPv3 credentials* | User name, auth/encryption algorithms and passwords must match exactly; passwords ≥ 8 characters. |
| Rates show *unavailable* | Normal for the first poll — a rate needs two samples. |
| An interface shows *(not currently reported)* | It was renamed or removed on the firewall; untick it. |

Enable debug logging with:

```yaml
logger:
  logs:
    custom_components.sophos_sfos: debug
```

## Development

Tests run against [snmpsim](https://github.com/lextudio/snmpsim) with a
synthetic SFOS 22 dataset (`tests/fixtures/sfos.snmprec`, generated by
`make_snmprec.py`):

```bash
python -m venv /tmp/sim && /tmp/sim/bin/pip install snmpsim pysmi cryptography
/tmp/sim/bin/snmpsim-command-responder --data-dir=tests/fixtures \
    --agent-udpv4-endpoint=127.0.0.1:1161 &
pip install -r requirements_test.txt
pytest
```

## License

MIT — © Mathew, N1MJF
