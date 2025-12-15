## Rebuild Bundle (copy this off‑VM)

This folder contains everything needed to redeploy the Elastic 9.2.2 stack and baseline agents in a fresh RHEL/Rocky VM.

### Contents
- `docs/`
  - `deployment-guide.md` — full stack redeploy + Fleet bootstrap + policy import order.
  - `baseline-runbook.md` — how to collect/export baselines; Windows packet‑capture “what worked” notes.
  - `ens-rule-mapping.md` — turning baseline exports into ENS/Trellix firewall rules.
- `policies/` — Fleet agent policy JSON exports to import.
- `scripts/` — idempotent Windows PowerShell + Linux Bash deploy/enroll scripts.
- `configs/network-device-templates/` — NetFlow/sFlow/syslog templates for Cisco/Palo/ESXi.
- `kibana/` — saved objects NDJSON (Network Baseline dashboard + searches).
- `agent-enrollment-package-windows/ENROLL-WINDOWS.txt` — reusable Windows enrollment steps.
- `stack-config/`
  - `elasticsearch.yml`, `kibana.yml` — known‑good configs (TLS on, single‑node).
  - `elastic-certs/` — current CA + service certs. You can reuse or regenerate; if you regenerate, update Fleet CA fingerprint per the guide.

### Rebuild order (high level)
1. Follow `docs/deployment-guide.md` starting at **Stack redeploy on RHEL/Rocky**.
2. Boot Fleet with **HTTPS output + CA fingerprint** (critical).
3. Import policies from `policies/` and create new enrollment tokens.
4. Import dashboard from `kibana/`.
5. Enroll endpoints using `scripts/` and the per‑policy tokens you created.

If you want a zipped copy for transfer: `tar -czf rebuild-bundle.tar.gz rebuild-bundle/`
