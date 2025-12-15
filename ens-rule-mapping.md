# ENS Firewall Rule Mapping Guide

## Inputs
- CSV exports from saved searches:
  - Unique source/destination/port combinations
  - Firewall allows
  - Firewall denies
  - DNS queries (for FQDN rules when available)
- Optional NetFlow summaries (top talkers, protocols).

## Rule design principles
- **Least privilege:** start from denies; add targeted allows for required flows.
- **Direction-aware:** use internal_networks to classify ingress vs egress.
- **Service specificity:** prefer dest IP/CIDR + port + protocol; use FQDN only for stable services.
- **Time-bounded:** maintenance/batch flows can be time-scoped.
- **Logging:** log first/deny rules and new allows for a probation period.

## Mapping steps
1. **Baseline deduplication:** dedupe source.ip + destination.ip + destination.port + network.transport.
2. **Classify flows:**
   - Trusted internal → candidate allow.
   - External egress → restrict to business destinations; deny/alert unknown.
   - Deny hits → confirm if legitimate; otherwise strengthen default deny.
3. **Group services:**
   - DNS: allow UDP/53 (and TCP/53 if seen) to resolvers only.
   - HTTPS app traffic: group by dest CIDR or sanctioned domains/SNI.
   - Directory/management: LDAP/LDAPS/Kerberos/SMB between servers and DCs.
   - Monitoring/backup: explicit ports and hosts.
4. **Draft ENS rules:**
   - Order: explicit allows → explicit denies for risky dests → default deny with log.
   - Include direction, local/remote ports, remote addresses, protocol.
   - Enable logging for all denies and new allows during tuning.
5. **Simulation/Tuning:**
   - Apply in “log-only” mode where supported.
   - Monitor ENS logs for new denies; compare against baseline exports.
6. **Cutover:**
   - Move stable allows to enforced state.
   - Keep deny logging permanently on critical zones.

## Recommended ENS rule structure (per flow class)
- **DNS:** Allow UDP/53 (and TCP/53 if observed) from endpoints to approved resolvers.
- **Web to SaaS:** Allow TCP/443 to sanctioned CIDRs/FQDNs; deny/alert others.
- **Admin/Management:** Allow RDP/SSH only from admin subnets to servers; log all other attempts.
- **Files/DB:** Allow SMB/SQL only between application tiers and databases; deny lateral SMB.
- **ICMP:** Allow echo within management VLANs if needed; deny external ICMP except diagnostics.

## Validation
- Post-rule deployment, compare ENS logs to baseline exports for unexpected denies.
- Re-run short (3–7 day) baselines after major changes to catch regressions.
