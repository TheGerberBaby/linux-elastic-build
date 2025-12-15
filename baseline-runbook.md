# Baseline Collection Runbook

## Objective
Gather network telemetry for 2–4 weeks to derive ENS firewall rules with minimal impact on mission-critical systems.

## Collection scope
- Windows: winlog (security logon IDs, WFP 5156–5159, firewall, DNS client), system socket/process, optional packet capture (DNS/HTTP/TLS/ICMP headers only).
- Linux: socket/process metrics, auditd network syscalls, auth/firewall logs.
- Network devices: NetFlow/IPFIX/sFlow on 2055/4739/6343; syslog on 1514 (TCP/TLS preferred).
- VMware: vCenter network metrics (120s), ESXi syslog.

### Windows packet capture note (what worked)
- Packet capture requires **Npcap** on the endpoint.
- On Windows, the `network_traffic` integration does **not** support `interface: any` or friendly names like `Wi‑Fi`. Leave `${CAPTURE_INTERFACE}` **blank/auto** for default capture, or set it to an Npcap device name/NPF GUID from `packetbeat.exe devices`.
- If packet capture is not needed on a given host, disable the `packet-capture-light` package policy to reduce overhead.

## Run duration
- Minimum: 2 weeks; Recommended: 4 weeks to cover weekday/weekend/maintenance patterns.

## Daily checks
1. Fleet → Agents: all healthy, no high CPU/mem on endpoints.
2. Kibana dashboard `Network Baseline`: confirm data flowing (no empty panels).
3. NetFlow collector queue: monitor `netflow` logs for drops; raise `queue_size` if drops seen.
4. Audit backlog: `auditctl -s` backlog not saturating; adjust backlog_limit if needed.

## Exporting baseline data
- Use saved searches (Saved Objects):
  - `Unique source/destination/port` → export CSV; deduplicate externally if needed.
  - `DNS queries` → export CSV.
  - `Firewall allows` / `Firewall denies` → export CSV.
- For NetFlow top talkers: run Kibana Lens/TSVB on `network.bytes` by `source.ip`, `destination.ip`, `destination.port`.
- Time range: full baseline window; apply filters for internal networks and critical subnets.

## Patterns to extract
- Persistent allow candidates: high-volume, recurring internal flows (e.g., domain controllers, patch servers).
- Rare external egress: candidate for explicit rules with logging; investigate deny hits.
- DNS: top domains; flag dynamic update traffic vs general browsing.
- TLS SNI (if captured) for sanctioned services vs unknown.
- ICMP: frequent pings between hosts (monitor vs allow).

## False positive avoidance
- Exclude break-glass/admin subnets from automated allow lists.
- Separate maintenance windows traffic from steady-state baseline.
- Treat one-time large transfers (e.g., backups) as scheduled rules with time windows.

## Close-out
- Confirm no data gaps in baseline period.
- Archive exported CSVs with hash and timestamp.
- Document open questions (unknown destinations, high-deny sources) before rule creation.
