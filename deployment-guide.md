# Deployment Guide - Lightweight Network Baselining with Elastic Agent

## Prerequisites
- Fleet Server reachable over TLS (URL and CA cert available).
- Elasticsearch/Kibana 9.x running.
- Enrollment token for each target policy.
- Outbound network allowed to Fleet Server (default 8220) and Elasticsearch if direct.
- Local artifact access for air-gapped installs (agent tar/zip).
- Windows: Admin PowerShell, Npcap installed for packet capture (optional).
- Linux: root/sudo, curl, tar; SELinux permissive or policy allowing agent/auditd access.

## Policies
- Windows: `policies/windows-network-baseline.json`
- Linux: `policies/linux-network-baseline.json`
- NetFlow/Syslog collector: `policies/netflow-syslog-collector.json`
- VMware: `policies/vmware-vsphere.json`

Import these in Fleet (Kibana → Fleet → Agent policies → Create/Import JSON) or apply via Fleet API.

## Stack redeploy on RHEL/Rocky (tar-based)
Use this to recreate the current 9.2.2 stack on a fresh RHEL/Rocky image. Paths assume `/opt/elastic`; adjust if you use a different root.

### 1. Host prep
- Open firewall ports you need: `9200/tcp` (ES), `5601/tcp` (Kibana), `8220/tcp` (Fleet Server). If you run collectors on this host, also open `2055/udp`, `4739/udp`, `6343/udp`, `1514/tcp+udp`.
- Install deps:
  ```bash
  sudo dnf install -y tar unzip curl openssl java-17-openjdk-headless
  ```
- Create service user (or reuse one):
  ```bash
  sudo useradd --system --home /opt/elastic --shell /sbin/nologin elastic || true
  sudo mkdir -p /opt/elastic && sudo chown -R elastic:elastic /opt/elastic
  ```

### 2. Elasticsearch
1. Extract the ES tarball:
   ```bash
   sudo mkdir -p /opt/elastic/elasticsearch/9.2.2
   sudo tar -xzf elasticsearch-9.2.2-linux-x86_64.tar.gz -C /opt/elastic/elasticsearch/9.2.2 --strip-components=1
   sudo chown -R elastic:elastic /opt/elastic/elasticsearch/9.2.2
   ```
2. Copy config and certs from this repo:
   ```bash
   sudo cp -a elasticsearch/9.2.2/config/elasticsearch.yml /opt/elastic/elasticsearch/9.2.2/config/
   sudo mkdir -p /opt/elastic/elasticsearch/9.2.2/config/certs
   sudo cp -a elastic-certs/elasticsearch/http.p12 /opt/elastic/elasticsearch/9.2.2/config/certs/
   sudo cp -a elastic-certs/elasticsearch/http_ca.crt /opt/elastic/elasticsearch/9.2.2/config/certs/
   sudo chown -R elastic:elastic /opt/elastic/elasticsearch/9.2.2/config/certs
   ```
3. Systemd unit (minimal example):
   ```ini
   # /etc/systemd/system/elasticsearch.service
   [Unit]
   Description=Elasticsearch
   After=network.target
   [Service]
   Type=simple
   User=elastic
   Group=elastic
   WorkingDirectory=/opt/elastic/elasticsearch/9.2.2
   ExecStart=/opt/elastic/elasticsearch/9.2.2/bin/elasticsearch
   LimitNOFILE=65535
   Restart=on-failure
   [Install]
   WantedBy=multi-user.target
   ```
4. Enable/start and verify:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now elasticsearch
   curl --cacert /opt/elastic/elasticsearch/9.2.2/config/certs/http_ca.crt https://localhost:9200
   ```

### 3. Built‑in user passwords
Set passwords (do not commit them to the repo):
```bash
sudo -u elastic /opt/elastic/elasticsearch/9.2.2/bin/elasticsearch-reset-password -u elastic -i
sudo -u elastic /opt/elastic/elasticsearch/9.2.2/bin/elasticsearch-reset-password -u kibana_system -i
```

### 4. Kibana
1. Extract Kibana:
   ```bash
   sudo mkdir -p /opt/elastic/kibana/9.2.2
   sudo tar -xzf kibana-9.2.2-linux-x86_64.tar.gz -C /opt/elastic/kibana/9.2.2 --strip-components=1
   sudo ln -sfn /opt/elastic/kibana/9.2.2 /opt/elastic/kibana/current
   sudo chown -R elastic:elastic /opt/elastic/kibana/9.2.2
   ```
2. Copy config and certs:
   ```bash
   sudo cp -a kibana/9.2.2/config/kibana.yml /opt/elastic/kibana/9.2.2/config/
   sudo mkdir -p /opt/elastic/kibana/9.2.2/config/certs
   sudo cp -a elastic-certs/elasticsearch/http.p12 /opt/elastic/kibana/9.2.2/config/certs/
   sudo cp -a elastic-certs/elasticsearch/http_ca.crt /opt/elastic/kibana/9.2.2/config/certs/
   sudo chown -R elastic:elastic /opt/elastic/kibana/9.2.2/config/certs
   ```
3. Create Kibana keystore and add the `kibana_system` password:
   ```bash
   sudo -u elastic /opt/elastic/kibana/9.2.2/bin/kibana-keystore create
   sudo -u elastic /opt/elastic/kibana/9.2.2/bin/kibana-keystore add elasticsearch.password
   ```
4. Systemd unit:
   ```ini
   # /etc/systemd/system/kibana.service
   [Unit]
   Description=Kibana
   After=network.target elasticsearch.service
   [Service]
   Type=simple
   User=elastic
   Group=elastic
   WorkingDirectory=/opt/elastic/kibana/9.2.2
   ExecStart=/opt/elastic/kibana/9.2.2/bin/kibana
   Restart=on-failure
   [Install]
   WantedBy=multi-user.target
   ```
5. Enable/start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now kibana
   ```

### 5. Fleet bootstrap (critical)
This environment only works when Fleet outputs use **HTTPS** and trust the ES CA. If the output is left on HTTP, agents go unhealthy.

1. Log into Kibana as `elastic`.
2. Fleet → Settings:
   - Fleet Server hosts: `https://<host_fqdn_or_ip>:8220`
   - Default output hosts: `https://<host_fqdn_or_ip>:9200`
   - Advanced YAML (default output):
     ```yaml
     ssl:
       ca_trusted_fingerprint: "<sha256_fingerprint_of_http_ca.crt>"
     ```
   Get the fingerprint with:
   ```bash
   openssl x509 -fingerprint -sha256 -noout -in /opt/elastic/elasticsearch/9.2.2/config/certs/http_ca.crt \
     | awk -F= '{print $2}' | tr -d :
   ```

### 6. Fleet Server (Elastic Agent)
1. Extract Elastic Agent:
   ```bash
   sudo mkdir -p /opt/elastic/elastic-agent/9.2.2
   sudo tar -xzf elastic-agent-9.2.2-linux-x86_64.tar.gz -C /opt/elastic/elastic-agent/9.2.2 --strip-components=1
   sudo ln -sfn /opt/elastic/elastic-agent/9.2.2 /opt/elastic/elastic-agent/current
   sudo chown -R elastic:elastic /opt/elastic/elastic-agent/9.2.2
   ```
2. In Fleet → Settings → Add Fleet Server, generate a **Fleet Server service token** and select/created a Fleet Server policy.
3. Install Fleet Server using repo certs:
   ```bash
   sudo /opt/elastic/elastic-agent/current/elastic-agent install \
     --fleet-server-es=https://localhost:9200 \
     --fleet-server-service-token=<fleet_service_token> \
     --fleet-server-policy=<fleet_server_policy_id> \
     --fleet-server-host=https://<host_fqdn_or_ip>:8220 \
     --certificate-authorities=/opt/elastic/elasticsearch/9.2.2/config/certs/http_ca.crt \
     --fleet-server-cert=/opt/elastic/elastic-certs/fleet-server/fleet-server.crt \
     --fleet-server-cert-key=/opt/elastic/elastic-certs/fleet-server/fleet-server.key \
     --non-interactive --force
   ```
4. Verify: Fleet → Agents shows Fleet Server healthy.

### 7. Import baseline policies and objects
1. Fleet → Agent policies → Create agent policy → Import JSON:
   - `policies/windows-network-baseline.json`
   - `policies/linux-network-baseline.json`
   - `policies/netflow-syslog-collector.json`
   - `policies/vmware-vsphere.json`
2. For each policy, create an enrollment token.
3. Import dashboard: Stack Management → Saved Objects → Import `kibana/network-baseline-dashboard.ndjson`.

## Windows deployment
1. Copy agent bundle, CA (`http_ca.crt`), and `scripts/deploy-windows.ps1`.
2. Run elevated PowerShell:
   ```powershell
   Set-Location <folder>
   .\deploy-windows.ps1 -FleetUrl "https://<fleet_host>:8220" -EnrollmentToken "<token>" -PolicyId "<policy_id>" -CaPath .\http_ca.crt
   ```
3. Verify: Services → Elastic Agent running, or `C:\Program Files\Elastic\Agent\elastic-agent.exe status`.
4. Optional: set capture interface in Fleet policy variable `${CAPTURE_INTERFACE}` to a specific Npcap name.

## Linux deployment
1. Copy agent tgz, CA, and `scripts/deploy-linux.sh`.
2. Run as root:
   ```bash
   FLEET_URL=https://<fleet_host>:8220 ENROLLMENT_TOKEN=<token> POLICY_ID=<policy_id> ./deploy-linux.sh --ca ./http_ca.crt --artifact ./elastic-agent-9.2.2-linux-x86_64.tar.gz
   ```
3. Verify: `systemctl status elastic-agent` and `/opt/Elastic/Agent/elastic-agent status`.

## NetFlow/Syslog collector
- Assign `netflow-syslog-collector` policy to a lightweight Linux host with open UDP 2055/4739/6343 and TCP/UDP 1514 (TLS certs for TCP).
- Apply device templates in `configs/network-device-templates/` (Cisco/Palo/ESXi/sFlow).

## VMware
- Create secrets for `${VCENTER_USERNAME}` and `${VCENTER_PASSWORD}` in Fleet.
- Import `vmware-vsphere.json` as a policy or package policy on the collector host.
- Configure ESXi syslog to `udp://<collector>:1515` per `configs/network-device-templates/esxi-syslog.txt`.

## Kibana objects
- Import `kibana/network-baseline-dashboard.ndjson` (Stack Management → Saved Objects).
- Data view: uses `logs-*` (edit if your streams differ).

## Troubleshooting
- Agent not enrolling: check CA path, firewall to 8220, token validity.
- No flow data: verify device export ports, collector host firewalls, NetFlow template version.
- Syslog TLS: confirm certificate/key paths and CN/SAN match collector host.
- Auditd conflicts: ensure no duplicate audit rules; backlog_limit set to 8192 in policy.
