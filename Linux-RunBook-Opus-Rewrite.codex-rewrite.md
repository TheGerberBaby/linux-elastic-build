#!/bin/bash

#   LINUX EDITION - Elastic Stack 9.2.x Secure Deployment & Update Repository
# ==============================================================================
# 
# AUTHOR: Antigravity for User
# DATE: 2025-12-07
# GOAL: Zero-Downtime-Ready Layout with Auto-Update Repository
#
# ======================================================
# 1. INITIAL SETUP & VARIABLES
# ======================================================
# Define versions (Update these if building a different version)
export ES_VER="9.2.2"
export KB_VER="9.2.2"
export AGENT_VER="9.2.2"

# Define Paths
export BASE_DIR="/opt/elastic"
export REPO_DIR="$BASE_DIR/repo"
export MOUNT_DATA="$BASE_DIR/elasticsearch/data"
export CERT_ROOT="$BASE_DIR/elastic-certs"
# Tarballs live under /opt/archive in this lab image
export SRC_ARCHIVE="/opt/archive"

# Passwords (CHANGE THESE!)
export PFX_PASS="password"

# Network
export HOST_IP=$(hostname -I | awk '{print $1}')
echo "Builder Configured: IP=$HOST_IP, Version=$ES_VER"

# Create User & Base Dirs
id -u elastic &>/dev/null || useradd -m elastic
mkdir -p "$BASE_DIR" "$REPO_DIR" "$CERT_ROOT"
chown -R elastic:elastic "$BASE_DIR"

# ======================================================
# 2. INSTALLATION (The "Current" Layout)
# ======================================================
echo ">>> Installing Elastic Stack from Archives..."

# We assume tarballs are in /opt/elastic/Archive (or download them here)
# For this runbook, we extract them to the versioned path.

mkdir -p "$BASE_DIR/elasticsearch/$ES_VER"
mkdir -p "$BASE_DIR/kibana/$KB_VER"
mkdir -p "$BASE_DIR/elastic-agent/$AGENT_VER"

# ==========================================
# EXTRACT ARCHIVES
# ==========================================
# Tip: If your file is named differently, just edit the filename in the command below.

# 1. EXTRACT ELASTICSEARCH
# Destination: /opt/elastic/elasticsearch/<version>
tar -xzf "$SRC_ARCHIVE/elasticsearch-$ES_VER-linux-x86_64.tar.gz" -C "$BASE_DIR/elasticsearch/$ES_VER" --strip-components=1

# 2. EXTRACT KIBANA
# Destination: /opt/elastic/kibana/<version>
tar -xzf "$SRC_ARCHIVE/kibana-$KB_VER-linux-x86_64.tar.gz" -C "$BASE_DIR/kibana/$KB_VER" --strip-components=1

# 3. EXTRACT ELASTIC AGENT
# Destination: /opt/elastic/elastic-agent/<version>
tar -xzf "$SRC_ARCHIVE/elastic-agent-$AGENT_VER-linux-x86_64.tar.gz" -C "$BASE_DIR/elastic-agent/$AGENT_VER" --strip-components=1

# Create 'current' symlinks (The Magic)
ln -sfn "$BASE_DIR/elasticsearch/$ES_VER" "$BASE_DIR/elasticsearch/current"
ln -sfn "$BASE_DIR/kibana/$KB_VER" "$BASE_DIR/kibana/current"
ln -sfn "$BASE_DIR/elastic-agent/$AGENT_VER" "$BASE_DIR/elastic-agent/current"

# Persistent Data Directory (Saving your data from upgrades)
mkdir -p "$MOUNT_DATA"
chown -R elastic:elastic "$BASE_DIR"

# Configure path.data
if ! grep -q "path.data" "$BASE_DIR/elasticsearch/current/config/elasticsearch.yml"; then
    echo "path.data: $MOUNT_DATA" >> "$BASE_DIR/elasticsearch/current/config/elasticsearch.yml"
fi

echo "[SUCCESS] Layout created."

# ======================================================
# 3. CERTIFICATES (Simplified)
# ======================================================
echo ">>> Generating Certificates..."
cd "$BASE_DIR/elasticsearch/current/bin"

# CA
./elasticsearch-certutil ca --out "$CERT_ROOT/elastic-stack-ca.p12" --pass "$PFX_PASS" --silent

# HTTP Cert (Interactive Mode)
# ------------------------------------------------------------------
# When prompted, enter at least one DNS name *and* IP address so TLS SANs
# match how you connect. Example answers:
#   Generate CSR?                       n
#   Use existing CA?                    y
#   CA Path:                            /opt/elastic/elastic-certs/elastic-stack-ca.p12
#   Password:                           password
#   Validity:                           365d
#   Generate per-node certs?            n
#   Hostnames:                          localhost
#                                        <blank line to finish>
#   IP Addresses:                       127.0.0.1
#                                        $HOST_IP
#                                        <blank line to finish>
#   Generate password?                  y
#   Output file:                        /opt/elastic/elasticsearch/$ES_VER/es-http.zip
# ------------------------------------------------------------------
./elasticsearch-certutil http

# Copy/rename the output so unzip always finds it
cp "$BASE_DIR/elasticsearch/$ES_VER/es-http.zip" "$BASE_DIR/elasticsearch/current/bin/es-http.zip"
# Unzip the generated file
unzip -o es-http.zip -d "$CERT_ROOT"
# Fleet Server PEM cert/key (used later by elastic-agent install)
mkdir -p "$CERT_ROOT/fleet-server"
./elasticsearch-certutil cert --name fleet-server \
  --ca "$CERT_ROOT/elastic-stack-ca.p12" --ca-pass "$PFX_PASS" \
  --dns localhost --ip "$HOST_IP" --pem \
  --out "$CERT_ROOT/fleet-server/fleet-server.zip"
unzip -o "$CERT_ROOT/fleet-server/fleet-server.zip" -d "$CERT_ROOT/fleet-server"
# Extract CA CRT for clients
openssl pkcs12 -in "$CERT_ROOT/elastic-stack-ca.p12" -out "$CERT_ROOT/elasticsearch/http_ca.crt" -clcerts -nokeys -passin "pass:$PFX_PASS"

# Copy to components
mkdir -p "$BASE_DIR/elasticsearch/current/config/certs"
mkdir -p "$BASE_DIR/kibana/current/config/certs"

cp "$CERT_ROOT/elasticsearch/http.p12" "$BASE_DIR/elasticsearch/current/config/certs/"
cp "$CERT_ROOT/elasticsearch/http_ca.crt" "$BASE_DIR/elasticsearch/current/config/certs/"
cp "$CERT_ROOT/elasticsearch/http.p12" "$BASE_DIR/kibana/current/config/certs/"
cp "$CERT_ROOT/elasticsearch/http_ca.crt" "$BASE_DIR/kibana/current/config/certs/"

chown -R elastic:elastic "$BASE_DIR"
chmod 755 "$BASE_DIR/elasticsearch/current/config/certs"

# ======================================================
# 4. CONFIGURATION (Elasticsearch & Kibana)
# ======================================================
echo ">>> Configuring Services..."

# ES Keystore (Interactive - Type 'y' to overwrite if asked)
cd "$BASE_DIR/elasticsearch/current/bin"
./elasticsearch-keystore create

# Add passwords (Type the password you set for the certs, e.g., 'password')
echo ">>> Adding HTTP SSL password..."
./elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password

echo ">>> Adding Transport SSL password (Keystore)..."
./elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password

echo ">>> Adding Transport SSL password (Truststore)..."
./elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password

# ES Config
cat > "$BASE_DIR/elasticsearch/current/config/elasticsearch.yml" <<EOF
cluster.name: cyber-elastic
node.name: node-1
network.host: 0.0.0.0
http.port: 9200
path.data: $MOUNT_DATA
discovery.type: single-node
xpack.security.enabled: true
xpack.security.http.ssl:
  enabled: true
  keystore.path: certs/http.p12
  verification_mode: certificate
xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  keystore.path: certs/http.p12
  truststore.path: certs/http.p12
EOF

# System Tweaks
sysctl -w vm.max_map_count=262144

# Start ES Temporarily to set passwords
echo ">>> Starting ES for Setup..."
chown -R elastic:elastic "$BASE_DIR"
# Start ES Temporarily to set passwords
echo ">>> Starting ES for Setup..."
# Ensure permissions are correct (Keystore was created as root, must be owned by elastic)
chown -R elastic:elastic "$BASE_DIR"
su elastic -c "$BASE_DIR/elasticsearch/current/bin/elasticsearch -d -p pid"
sleep 45

# Reset Passwords
cd "$BASE_DIR/elasticsearch/current/bin"
export ELASTIC_BOOT_PWD=$(./elasticsearch-reset-password -u elastic -b | awk '/New value/ {print $3}')
echo "elastic superuser password: $ELASTIC_BOOT_PWD"
export KIBANA_SYSTEM_PWD=$(./elasticsearch-reset-password -u kibana_system -b | awk '/New value/ {print $3}')
echo "kibana_system password: $KIBANA_SYSTEM_PWD"
cat > "$BASE_DIR/passwords.txt" <<PASSFILE
elastic=$ELASTIC_BOOT_PWD
kibana_system=$KIBANA_SYSTEM_PWD
PASSFILE
chmod 600 "$BASE_DIR/passwords.txt"

# (Note: In a script we might use --batch or expect interaction. For this runbook, assume interactive or auto-generated.)
# FOR AUTOMATION: We will set known passwords or use output. 
# User wanted "easy", so let's stick to the generated ones or ask user to run reset manually if needed.
# For this verified build, I'll let it autogenerate and assume the user grabs them unless I force them.
# BETTER: Force 'password' for easy testing if possible? No, insecure. 
# I will run auto and print it.

echo ">>> Configuring Kibana..."
# Kibana Keystore (Interactive)
cd "$BASE_DIR/kibana/current/bin"
./kibana-keystore create

echo ">>> Adding Kibana SSL password..."
printf '%s\n' "$PFX_PASS" | ./kibana-keystore add server.ssl.keystore.password -x

echo ">>> Adding Elasticsearch Password (for kibana_system user)..."
printf '%s\n' "$KIBANA_SYSTEM_PWD" | ./kibana-keystore add elasticsearch.password -x

# Kibana Config
cat > "$BASE_DIR/kibana/current/config/kibana.yml" <<EOF
server.host: "0.0.0.0"
server.ssl.enabled: true
server.ssl.keystore.path: "$BASE_DIR/kibana/current/config/certs/http.p12"
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.ssl.certificateAuthorities: ["$BASE_DIR/kibana/current/config/certs/http_ca.crt"]
elasticsearch.ssl.verificationMode: none
xpack.security.encryptionKey: "12345678901234567890123456789012"
xpack.encryptedSavedObjects.encryptionKey: "12345678901234567890123456789012"
xpack.reporting.encryptionKey: "12345678901234567890123456789012"
EOF

# Kill temp ES
pkill -u elastic -f "elasticsearch"

# ======================================================
# 5. SERVICE CREATION (Systemd)
# ======================================================
echo ">>> Creating Systemd Units..."

cat <<EOF > /etc/systemd/system/elasticsearch.service
[Unit]
Description=Elasticsearch
After=network.target
[Service]
Type=simple
User=elastic
Group=elastic
WorkingDirectory=$BASE_DIR/elasticsearch/current
ExecStart=$BASE_DIR/elasticsearch/current/bin/elasticsearch
LimitNOFILE=65535
TimeoutStopSec=20
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/kibana.service
[Unit]
Description=Kibana
After=network.target elasticsearch.service
[Service]
Type=simple
User=elastic
Group=elastic
WorkingDirectory=$BASE_DIR/kibana/current
ExecStart=$BASE_DIR/kibana/current/bin/kibana
LimitNOFILE=65535
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now elasticsearch kibana


# ======================================================
# 6. FLEET SERVER SETUP (Verified CLI Method)
# ======================================================
# This configures the Elastic Agent on this host to act as the Fleet Server.
# The `elastic-agent install` command below creates /opt/Elastic/Agent and installs/starts the systemd unit, so no manual unit file is required.

# 0. PRE-FLIGHT CHECK & RESET (Always run this if retrying)
echo ">>> preparing fresh agent binary..."
systemctl stop elastic-agent || true
/opt/elastic/elastic-agent/current/elastic-agent uninstall --force || true
rm -rf /etc/systemd/system/elastic-agent.service
rm -rf /opt/Elastic/Agent
# Re-extract to ensure clean binary under /opt/elastic/elastic-agent/<ver>
rm -rf "$BASE_DIR/elastic-agent/$AGENT_VER"
mkdir -p "$BASE_DIR/elastic-agent/$AGENT_VER"
tar -xzf "$SRC_ARCHIVE/elastic-agent-$AGENT_VER-linux-x86_64.tar.gz" -C "$BASE_DIR/elastic-agent/$AGENT_VER" --strip-components=1

# 0.5 Fleet bootstrap via Kibana API (ensures Fleet Server policy/hosts exist)
ELASTIC_BOOT_PWD=$(awk -F= '/elastic=/{print $2}' "$BASE_DIR/passwords.txt")
echo ">>> Initializing Fleet (Kibana API)..."
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/setup" \
  -H 'kbn-xsrf: true' >/dev/null
FLEET_POLICY_ID=$(curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/agent_policies" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"name":"fleet-server-policy","description":"Fleet Server policy","namespace":"default","is_default_fleet_server":true}' \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "Fleet policy id: $FLEET_POLICY_ID"
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/fleet_server_hosts" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d "{\"name\": \"local-fleet-host\", \"host_urls\": [\"https://$HOST_IP:8220\"], \"is_default\": true}" >/dev/null

# IMPORTANT: before installing the agent, run the HTTPS output hardening in Appendix G so Fleet's default output uses
# https://localhost:9200 with the CA fingerprint. The install will fail if Fleet is still pointing at http://localhost:9200.

# 0.6 Attach the Fleet Server integration to the policy (prevents install from hanging)
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/package_policies" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d "{
        \"name\":\"fleet-server\",
        \"namespace\":\"default\",
        \"policy_id\":\"$FLEET_POLICY_ID\",
        \"package\":{\"name\":\"fleet_server\",\"version\":\"1.6.0\"},
        \"inputs\":[{\"type\":\"fleet-server\",\"enabled\":true,\"streams\":[]}]
      }" \
  | grep -vq '\"error\"' || echo "[INFO] Fleet Server integration already exists (safe to ignore)."

# 1. GENERATE SERVICE TOKEN (run as elastic so service_tokens file has correct ownership)
cd "$BASE_DIR/elasticsearch/current/bin"
echo ">>> Generating Service Token..."
su -s /bin/bash elastic -c "./elasticsearch-service-tokens delete elastic/fleet-server fleet-token-1" 2>/dev/null || true
SERVICE_TOKEN=$(su -s /bin/bash elastic -c "./elasticsearch-service-tokens create elastic/fleet-server fleet-token-1" | awk -F'=' '{print $2}' | tr -d ' ')
echo "Token: $SERVICE_TOKEN"

# 2. INSTALL FLEET SERVER
cd "$BASE_DIR/elastic-agent/current"
echo ">>> Installing Fleet Server (Port 8220)..."
./elastic-agent install \
  --certificate-authorities "$BASE_DIR/elasticsearch/current/config/certs/http_ca.crt" \
  --url="https://$HOST_IP:8220" \
  --fleet-server-es="https://$HOST_IP:9200" \
  --fleet-server-service-token="$SERVICE_TOKEN" \
  --fleet-server-policy="$FLEET_POLICY_ID" \
  --fleet-server-es-ca="$BASE_DIR/elasticsearch/current/config/certs/http_ca.crt" \
  --fleet-server-cert="$CERT_ROOT/fleet-server/fleet-server/fleet-server.crt" \
  --fleet-server-cert-key="$CERT_ROOT/fleet-server/fleet-server/fleet-server.key" \
  --force
# if you have to uninstall the agent and try again its here /opt/Elastic/Agent/elastic-agent uninstall --force

# 2.5 ENSURE FLEET SERVER POLICY SHIPS METRICS (Logs + Metrics)
# Re-export credentials (new shells lose ELASTIC_BOOT_PWD) and force the policy to turn on monitoring so the Fleet UI shows
# elastic-agent metrics immediately.
ELASTIC_BOOT_PWD=$(awk -F= '/^elastic=/{print $2}' "$BASE_DIR/passwords.txt")
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  -X PUT "https://localhost:5601/api/fleet/agent_policies/${FLEET_POLICY_ID}" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d "{\"name\":\"fleet-server-policy\",\"namespace\":\"default\",\"description\":\"Fleet Server policy\",\"monitoring_enabled\":[\"logs\",\"metrics\"]}"
systemctl restart elastic-agent
/opt/Elastic/Agent/elastic-agent status
# Fleet > Agents should now show “Agent monitoring: Logs & Metrics” and the Metrics tab will populate for the Fleet Server.

# ======================================================
# 7. POST-FLEET CONSOLIDATED WORKFLOW (METRICS ➜ REPO ➜ REMOTE AGENTS)
# ======================================================
# Follow this section immediately after Fleet Server enrollment. It captures everything the appendices covered so you
# can stay in one flow.

# --- 7.1 TURN ON AGENT MONITORING (LOGS + METRICS) ---
# Required for every policy (Fleet Server + workload policies).
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  -X PUT "https://localhost:5601/api/fleet/agent_policies/${FLEET_POLICY_ID}" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d "{\"name\":\"fleet-server-policy\",\"namespace\":\"default\",\"description\":\"Fleet Server policy\",\"monitoring_enabled\":[\"logs\",\"metrics\"]}"
# Repeat the PUT for linux-network-baseline, windows-network-baseline, netflow collector, vmware, etc.

# --- 7.2 IMPORT BASELINE POLICIES (FROM rebuild-bundle/policies/) ---
# Files and what they collect:
#   linux-network-baseline.json  -> system socket/process metrics, auditd network syscalls, auth/firewall logs.
#   windows-network-baseline.json -> system socket/process metrics, winlog (Security/System/Application), network_traffic DNS/HTTP/TLS/ICMP.
#   netflow-syslog-collector.json -> NetFlow/IPFIX/sFlow listeners + TLS syslog.
#   vmware-vsphere.json          -> vSphere/ESXi performance + syslog.
# GUI path: Kibana > Fleet > Agent policies > Create agent policy > Import JSON.
# API option:
#   curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
#     -X POST "https://localhost:5601/api/fleet/agent_policies?sys_monitoring=true" \
#     -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
#     -d @/opt/archive/rebuild-bundle/policies/<policy>.json
# After each import, open the policy, confirm “Agent monitoring: Logs & Metrics”, and create an enrollment token.

# --- 7.3 DASHBOARDS / SAVED OBJECTS ---
# Kibana > Stack Management > Saved Objects > Import /opt/archive/rebuild-bundle/kibana/network-baseline-dashboard.ndjson.
# Set default data view to logs-* so the baseline dashboard is populated.
# Create a dedicated Discover view for auditors to browse Windows event logs without crafting filters:
#   curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
#     -X POST "https://localhost:5601/api/data_views/data_view" \
#     -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
#     -d '{"data_view":{"id":"winlog-events","title":"logs-system.security-*","name":"Winlog events","timeFieldName":"@timestamp"}}'
# Kibana > Discover > Data view: Winlog events now loads the `logs-system.security-*` stream (Security/Firewall/DNS). Save a "Winlog" workspace
# for auditors if needed. CLI spot check:
#   curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
#     "https://192.168.1.164:9200/logs-system.security-*/_search?size=1&filter_path=hits.total.value,hits.hits._source.agent.name,hits.hits._source.winlog.channel,hits.hits._source.event.code"

# --- 7.4 WINDOWS POLICY (API BUILD + TOKEN) ---
WINDOWS_POLICY_JSON=/tmp/windows-policy.json
cat <<'EOF' >"$WINDOWS_POLICY_JSON"
{
  "name": "windows-network-baseline",
  "namespace": "default",
  "description": "Lightweight network baseline for Windows endpoints (minimal resource usage, TLS-enabled Fleet output).",
  "monitoring_enabled": ["logs", "metrics"]
}
EOF
WINDOWS_POLICY_ID=$(curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  -X POST "https://localhost:5601/api/fleet/agent_policies?sys_monitoring=true" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d @"$WINDOWS_POLICY_JSON" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "WINDOWS_POLICY_ID=$WINDOWS_POLICY_ID"

# Attach system metrics (CPU/mem/disk/network/process/socket summary)
cat <<EOF >/tmp/windows-system-network-events.json
{
  "name": "system-network-events",
  "namespace": "default",
  "policy_id": "$WINDOWS_POLICY_ID",
  "package": { "name": "system", "version": "2.8.0" },
  "inputs": [
    {
      "type": "system/metrics",
      "policy_template": "system",
      "enabled": true,
      "streams": [
        { "enabled": true, "data_stream": { "type": "metrics", "dataset": "system.cpu" }, "vars": { "period": { "value": "60s" }, "cpu.metrics": { "value": ["percentages", "normalized_percentages"] } } },
        { "enabled": true, "data_stream": { "type": "metrics", "dataset": "system.memory" }, "vars": { "period": { "value": "60s" } } },
        { "enabled": true, "data_stream": { "type": "metrics", "dataset": "system.diskio" }, "vars": { "period": { "value": "60s" }, "diskio.include_devices": { "value": [] } } },
        { "enabled": true, "data_stream": { "type": "metrics", "dataset": "system.network" }, "vars": { "period": { "value": "60s" }, "network.interfaces": { "value": [] } } },
        { "enabled": true, "data_stream": { "type": "metrics", "dataset": "system.socket_summary" }, "vars": { "period": { "value": "60s" } } },
        { "enabled": true, "data_stream": { "type": "metrics", "dataset": "system.process" }, "vars": { "period": { "value": "60s" }, "process.include_top_n.by_cpu": { "value": 0 }, "process.include_top_n.by_memory": { "value": 0 }, "processes": { "value": [".*"] }, "process.include_cpu_ticks": { "value": false }, "process.cmdline.cache.enabled": { "value": true } } }
      ],
      "vars": { "system.hostfs": { "value": "" } }
    }
  ]
}
EOF
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/package_policies" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d @/tmp/windows-system-network-events.json >/dev/null

# Attach winlog collection (Security + Firewall + DNS channels)
cat <<EOF >/tmp/windows-winlog-events.json
{
  "name": "windows-winlog-events",
  "namespace": "default",
  "policy_id": "$WINDOWS_POLICY_ID",
  "package": { "name": "system", "version": "2.8.0" },
  "inputs": [
    {
      "type": "winlog",
      "policy_template": "system",
      "enabled": true,
      "streams": [
        {
          "enabled": true,
          "data_stream": { "type": "logs", "dataset": "system.security" },
          "vars": {
            "preserve_original_event": { "value": false },
            "ignore_older": { "value": "0s" },
            "custom": { "value": "event_logs:\\n  - name: Security\\n    event_id: 4624,4625,4648,5156,5157,5158,5159\\n    ignore_older: 0s\\n  - name: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\\n    ignore_older: 0s\\n  - name: Microsoft-Windows-DNS-Client/Operational\\n    ignore_older: 0s\\n  - name: System\\n    ignore_older: 0s\\n  - name: Application\\n    ignore_older: 72h" }
          }
        }
      ]
    }
  ]
}
EOF
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/package_policies" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d @/tmp/windows-winlog-events.json >/dev/null

# Attach packet capture on both Ethernet + Wi-Fi interfaces (Fleet vars drive interface bindings)
cat <<EOF >/tmp/windows-packet-capture.json
{
  "name": "packet-capture-light",
  "namespace": "default",
  "policy_id": "$WINDOWS_POLICY_ID",
  "package": { "name": "network_traffic", "version": "1.34.0" },
  "inputs": [
    {
      "type": "packet",
      "policy_template": "network",
      "enabled": true,
      "vars": { "interface": { "value": "${CAPTURE_INTERFACE_ETHERNET:}" }, "with_vlans": { "value": true }, "ignore_outgoing": { "value": false } },
      "streams": [
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.dns" }, "vars": { "port": { "value": [53] }, "geoip_enrich": { "value": true }, "monitor_processes": { "value": true } } },
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.http" }, "vars": { "port": { "value": [80,8080,8000,5000,8002] }, "send_headers": { "value": [] }, "include_body_for": { "value": [] }, "monitor_processes": { "value": true }, "map_to_ecs": { "value": true } } },
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.tls" }, "vars": { "port": { "value": [443,993,995,5223,8443,8883,9243] }, "geoip_enrich": { "value": true }, "monitor_processes": { "value": true }, "send_certificates": { "value": false }, "include_raw_certificates": { "value": false }, "map_to_ecs": { "value": true } } },
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.icmp" }, "vars": { "geoip_enrich": { "value": true }, "monitor_processes": { "value": true }, "map_to_ecs": { "value": true } } }
      ]
    },
    {
      "type": "packet",
      "policy_template": "network",
      "enabled": true,
      "vars": { "interface": { "value": "${CAPTURE_INTERFACE_WIFI:}" }, "with_vlans": { "value": true }, "ignore_outgoing": { "value": false } },
      "streams": [
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.dns" }, "vars": { "port": { "value": [53] }, "geoip_enrich": { "value": true }, "monitor_processes": { "value": true } } },
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.http" }, "vars": { "port": { "value": [80,8080,8000,5000,8002] }, "send_headers": { "value": [] }, "include_body_for": { "value": [] }, "monitor_processes": { "value": true }, "map_to_ecs": { "value": true } } },
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.tls" }, "vars": { "port": { "value": [443,993,995,5223,8443,8883,9243] }, "geoip_enrich": { "value": true }, "monitor_processes": { "value": true }, "send_certificates": { "value": false }, "include_raw_certificates": { "value": false }, "map_to_ecs": { "value": true } } },
        { "enabled": true, "data_stream": { "type": "logs", "dataset": "network_traffic.icmp" }, "vars": { "geoip_enrich": { "value": true }, "monitor_processes": { "value": true }, "map_to_ecs": { "value": true } } }
      ]
    }
  ]
}
EOF
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/package_policies" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d @/tmp/windows-packet-capture.json >/dev/null

# Enrollment token for distribution (store securely; rotate per deployment)
WINDOWS_POLICY_TOKEN=$(curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  -X POST "https://localhost:5601/api/fleet/enrollment_api_keys" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d "{\"policy_id\":\"$WINDOWS_POLICY_ID\"}" \
  | grep -o '"api_key":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "WINDOWS_POLICY_TOKEN=$WINDOWS_POLICY_TOKEN"

# --- 7.4 REMOTE AGENT DEPLOYMENT CHEAT SHEET ---
# Linux endpoints:
#   FLEET_URL=https://$HOST_IP:8220 ENROLLMENT_TOKEN=<token> POLICY_ID=<linux_policy_id> \
#     ./deploy-linux.sh --ca ./http_ca.crt --artifact ./elastic-agent-$AGENT_VER-linux-x86_64.tar.gz
# Windows endpoints (PowerShell, elevated):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\deploy-windows.ps1 -FleetUrl "https://$HOST_IP:8220" -EnrollmentToken "<token>" `
#       -PolicyId "<windows_policy_id>" -CaPath .\http_ca.crt -ArtifactPath .\elastic-agent-$AGENT_VER-windows-x86_64.zip
#   Use `${CAPTURE_INTERFACE}` in the policy to bind packet capture to the right NIC.

# --- 7.4.1 STAGE WINDOWS MANUAL ENROLLMENT PACKAGE ---
WINDOWS_PKG_DIR="$SRC_ARCHIVE/rebuild-bundle/agent-enrollment-package-windows"
WINDOWS_PKG_ZIP="$SRC_ARCHIVE/rebuild-bundle/agent-enrollment-package-windows.zip"
rm -rf "$WINDOWS_PKG_DIR"
mkdir -p "$WINDOWS_PKG_DIR/scripts" "$WINDOWS_PKG_DIR/policies"
cp "$SRC_ARCHIVE/elastic-agent-$AGENT_VER-windows-x86_64.zip" "$WINDOWS_PKG_DIR/"
cp "$CERT_ROOT/elasticsearch/http_ca.crt" "$WINDOWS_PKG_DIR/"
cp "$SRC_ARCHIVE/rebuild-bundle/scripts/deploy-windows.ps1" "$WINDOWS_PKG_DIR/scripts/"
cp "$SRC_ARCHIVE/rebuild-bundle/policies/windows-network-baseline.json" "$WINDOWS_PKG_DIR/policies/"
cat > "$WINDOWS_PKG_DIR/ENROLL-WINDOWS.txt" <<'EOF'
Windows Elastic Agent manual enrollment (run from an elevated PowerShell prompt):

1. Unzip the package (if you received the `.zip` wrapper):
   ```
   Expand-Archive -Path .\agent-enrollment-package-windows.zip -DestinationPath .
   Set-Location .\agent-enrollment-package-windows
   ```

2. Unzip the Elastic Agent artifact and move into the binary folder:
   ```
   Expand-Archive -Path .\elastic-agent-9.2.2-windows-x86_64.zip -DestinationPath .\elastic-agent-9.2.2
   Set-Location .\elastic-agent-9.2.2\elastic-agent-9.2.2-windows-x86_64
   ```

3. Populate the required variables with the values from Kibana → Fleet → Agent policies:
   ```
   $FleetUrl = "https://<fleet_server_host>:8220"
   $EnrollmentToken = "<windows_policy_enrollment_token>"
   $CA = (Resolve-Path ..\..\http_ca.crt).Path
   ```
   - Enrollment tokens are scoped to a policy, so no `--policy-id` flag is needed on modern Elastic Agent builds.

4. (Optional but recommended) Pin the Ethernet and Wi-Fi adapters that should run packet capture by setting the `CAPTURE_INTERFACE_*` environment variables before installing:
   ```
   Get-NetAdapter | Format-Table Name, Status, InterfaceDescription, InterfaceGuid
   # Replace the GUIDs below with ones from the adapters you want to monitor.
   setx CAPTURE_INTERFACE_ETHERNET "\\Device\\NPF_{A1B2C3D4-....}"
   setx CAPTURE_INTERFACE_WIFI "\\Device\\NPF_{E5F6A7B8-....}"
   ```
   - Use the Npcap name reported by `packetbeat.exe devices` if you prefer (`.\packetbeat.exe devices` from this folder).
   - Leave a value blank (or remove the env var) if the host does not use that media type.

5. Install and enroll the agent (non-interactive):
   ```
   .\elastic-agent.exe install `
     --url $FleetUrl `
     --enrollment-token $EnrollmentToken `
     --certificate-authorities $CA `
     --non-interactive --force
   # Append --insecure if the endpoint cannot validate http_ca.crt yet (temporary workaround).
   ```

6. Validate the service:
   ```
   Get-Service elastic-agent
   & "C:\Program Files\Elastic\Agent\elastic-agent.exe" status
   ```

Optional: the package also contains `.\scripts\deploy-windows.ps1`, which performs steps 3–6 automatically (and auto-detects adapters). Pass `-CaptureInterface*` or `-Insecure` to mirror the manual flags.

Historical Winlog replay (pull every retained Security/System entry plus DNS/Firewall/Application without waiting for new events):
```
Stop-Service elastic-agent
Get-ChildItem "C:\Program Files\Elastic\Agent\data" -Directory -Filter "elastic-agent-*" | ForEach-Object {
  $state = Join-Path $_.FullName "logs\default\winlogbeat\state"
  if (Test-Path $state) {
    Remove-Item $state -Recurse -Force
  }
}
Start-Service elastic-agent
```
# The winlog dataset now sets ignore_older=0s, so clearing the checkpoint above causes Elastic Agent to replay the full Windows event logs (can take several minutes).
# Application channel remains capped at ignore_older=72h by policy so auditors can focus on recent app warnings without overwhelming the index.

Fleet-managed replay (no endpoint access required):
```
WINDOWS_WINLOG_POLICY_ID=$(curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  "https://localhost:5601/api/fleet/package_policies?perPage=200&kuery=name:windows-winlog-events" \
  -H 'kbn-xsrf: true' | jq -r '.items[0].id')
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  "https://localhost:5601/api/fleet/package_policies/${WINDOWS_WINLOG_POLICY_ID}" \
  -H 'kbn-xsrf: true' > /tmp/windows-winlog-policy.json
/usr/libexec/platform-python - <<'PY'
import json
with open('/tmp/windows-winlog-policy.json') as f:
    data=json.load(f)
item=data['item']
for inp in item.get('inputs', []):
    for stream in inp.get('streams', []):
        stream.pop('compiled_stream', None)
        stream.setdefault('vars',{})['start_at']={'value':'beginning'}
with open('/tmp/windows-winlog-update.json','w') as f:
    json.dump({
        'name': item['name'],
        'namespace': item.get('namespace','default'),
        'description': item.get('description',''),
        'policy_id': item['policy_id'],
        'enabled': item.get('enabled', True),
        'inputs': item['inputs'],
        'version': item.get('version')
    }, f)
PY
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  -X PUT "https://localhost:5601/api/fleet/package_policies/${WINDOWS_WINLOG_POLICY_ID}" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  --data-binary @/tmp/windows-winlog-update.json >/tmp/windows-winlog-response.json
```
# Elastic Agent downloads the updated policy, resets its checkpoint automatically, and ingests the full backlog. Expect increased CPU/network until the Windows Event Log queue drains.

Revert once auditors confirm historical coverage (prevents a replay on every restart):
```
/usr/libexec/platform-python - <<'PY'
import json
with open('/tmp/windows-winlog-policy.json') as f:
    data=json.load(f)
item=data['item']
for inp in item.get('inputs', []):
    for stream in inp.get('streams', []):
        stream.pop('compiled_stream', None)
        stream.setdefault('vars',{})['start_at']={'value':'now'}
with open('/tmp/windows-winlog-now.json','w') as f:
    json.dump({
        'name': item['name'],
        'namespace': item.get('namespace','default'),
        'description': item.get('description',''),
        'policy_id': item['policy_id'],
        'enabled': item.get('enabled', True),
        'inputs': item['inputs'],
        'version': item.get('version')
    }, f)
PY
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  -X PUT "https://localhost:5601/api/fleet/package_policies/${WINDOWS_WINLOG_POLICY_ID}" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  --data-binary @/tmp/windows-winlog-now.json >/tmp/windows-winlog-response.json
```
# Keep `start_at: now` for day-to-day operations; only flip it back to "beginning" during planned historical replays.

Notes:
- Ensure Elasticsearch/Fleet use HTTPS with the bundled CA (`http_ca.crt`) and that TCP/8220 is reachable.
- Set a new enrollment token scoped to the `windows-network-baseline` policy each time you stage this package.
EOF
pushd "$SRC_ARCHIVE/rebuild-bundle"
rm -f "$(basename "$WINDOWS_PKG_ZIP")"
zip -r "$(basename "$WINDOWS_PKG_ZIP")" agent-enrollment-package-windows
popd
echo "Windows enrollment package staged at $WINDOWS_PKG_ZIP"

# NetFlow/Syslog collector: enroll a Linux VM with the netflow policy, open UDP 2055/4739/6343 + TCP/UDP 1514, supply TLS certs.
# VMware collector: populate ${VCENTER_HOST}, secrets for ${VCENTER_USERNAME}/${VCENTER_PASSWORD}, point ESXi syslog to udp://collector:1515.

# --- 7.5 LOCAL REPO (SUMMARY) ---
# If you skipped Section 8 earlier, run it now. Once httpd is serving /opt/elastic/agent-repo and Fleet knows about
# http://$HOST_IP:8081/downloads/, any upgrade triggered from Fleet will pull from your local archive.

# --- 7.6 HEALTH VERIFICATION ---
#   curl -s -k https://localhost:8220/api/status | jq '.status'   # "HEALTHY"
#   Fleet > Agents shows Fleet Server + new endpoints online.
#   /opt/Elastic/Agent/elastic-agent status                       # monitors healthy
#   Kibana network baseline dashboard displays socket/process/auth panels per host.

# --- 7.7 OPTIONAL: BACKFILL EXISTING LOG FILES (READ FROM BEGINNING) ---
# Verified on 2025-12-14: the Fleet Server host is now shipping every line from /var/log/*.log (dnf history from
# 2025-12-11 shows up under `logs-system.syslog-default`). To reproduce on a fresh build:
ELASTIC_BOOT_PWD=$(awk -F= '/elastic=/{print $2}' "$BASE_DIR/passwords.txt")
# (FLEET_POLICY_ID is already exported during Fleet policy creation; re-export it here if your shell was reset.)
FLEET_POLICY_ID=$(curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  "https://localhost:5601/api/fleet/agent_policies?perPage=100" \
  -H 'kbn-xsrf: true' \
  | grep -B2 '"name":"fleet-server-policy"' | grep '"id":"' | head -1 | cut -d':' -f2 | tr -d '\" ,')
# 1) Make sure the System integration is available, then attach a logfile policy to the Fleet Server.
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/epm/packages/system-2.8.0" \
  -H 'kbn-xsrf: true'
cat <<'EOF' >/tmp/fleet-server-system-logs.json
{
  "name": "fleet-server-system-logs",
  "description": "Ship all historical Linux auth/syslog files from the Fleet Server host",
  "namespace": "default",
  "policy_id": "FLEET_POLICY_ID_PLACEHOLDER",
  "package": { "name": "system", "version": "2.8.0" },
  "inputs": [
    {
      "type": "logfile",
      "enabled": true,
      "streams": [
        {
          "enabled": true,
          "data_stream": { "type": "logs", "dataset": "system.auth" },
          "vars": {
            "paths": { "value": ["/var/log/auth.log", "/var/log/secure"] },
            "ignore_older": { "value": "0" },
            "preserve_original_event": { "value": false }
          }
        },
        {
          "enabled": true,
          "data_stream": { "type": "logs", "dataset": "system.syslog" },
          "vars": {
            "paths": { "value": ["/var/log/messages*", "/var/log/syslog*", "/var/log/system*", "/var/log/*.log"] },
            "ignore_older": { "value": "0" },
            "preserve_original_event": { "value": false }
          }
        }
      ]
    }
  ]
}
EOF
sed -i "s/FLEET_POLICY_ID_PLACEHOLDER/${FLEET_POLICY_ID}/" /tmp/fleet-server-system-logs.json
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/package_policies" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d @/tmp/fleet-server-system-logs.json

# 2) Restart the local agent so it picks up the new log input and starts reading each file from byte 0.
systemctl restart elastic-agent
sleep 90
/opt/Elastic/Agent/elastic-agent status

# 3) Confirm historical data arrived (look for timestamps that pre-date the install).
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  "https://localhost:9200/logs-system.syslog-default/_search?size=3&sort=@timestamp:asc&filter_path=hits.hits._source.@timestamp,hits.hits._source.log.file.path,hits.hits._source.message"
# Sample output (showing 2025-12-11 dnf history backfill):
# {
#   "hits": {
#     "hits": [
#       {
#         "_source": {
#           "@timestamp": "2025-12-11T23:12:47.000-05:00",
#           "log": { "file": { "path": "/var/log/dnf.rpm.log" } },
#           "message": "INFO --- logging initialized ---"
#         }
#       },
#       {
#         "_source": {
#           "@timestamp": "2025-12-11T23:12:47.000-05:00",
#           "log": { "file": { "path": "/var/log/dnf.librepo.log" } },
#           "message": "https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=AppStream-8"
#         }
#       }
#     ]
#   }
# }

# Repeat the same pattern for other policies (Windows baseline, etc.) by attaching their log integrations with
# `ignore_older: 0`. When rerunning on a host that already ingested logs, delete or move the Elastic Agent
# registry (Linux: /opt/Elastic/Agent/data/elastic-agent-*/state.enc) before restarting so the harvester replays
# every file. Expect a spike in disk, CPU, and ingest rate while backfilling.

# ======================================================
# 8. LOCAL REPO & AUTO-UPDATE SETUP
# ======================================================
echo ">>> Building Auto-Update Repo..."

mkdir -p "$REPO_DIR/incoming" "$REPO_DIR/archive" "$REPO_DIR/logs"

# 8.1 Install the lightweight Apache repo (port 8081 defaults)
# Keep these commands handy for any rebuild; the repo lets Fleet download upgrades without Internet access.
dnf install -y httpd policycoreutils-python-utils
mkdir -p /opt/elastic/agent-repo/downloads/beats/elastic-agent
mkdir -p /opt/elastic/agent-repo/downloads/fleet-server

# Copy at least the Linux agent tarball into the repo tree and generate the SHA512 Fleet expects.
cp "$SRC_ARCHIVE/elastic-agent-$AGENT_VER-linux-x86_64.tar.gz" \
   "/opt/elastic/agent-repo/downloads/beats/elastic-agent/"
cd /opt/elastic/agent-repo/downloads/beats/elastic-agent
sha512sum "elastic-agent-$AGENT_VER-linux-x86_64.tar.gz" > \
          "elastic-agent-$AGENT_VER-linux-x86_64.tar.gz.sha512"

# 8.2 Serve the repo over HTTP/8081 (Apache + SELinux adjustments)
cat > /etc/httpd/conf.d/agent-repo.conf <<'EOCONF'
Listen 8081
<VirtualHost *:8081>
    DocumentRoot /opt/elastic/agent-repo
    <Directory /opt/elastic/agent-repo>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOCONF
chmod -R 755 /opt/elastic/agent-repo
semanage port -a -t http_port_t -p tcp 8081 || semanage port -m -t http_port_t -p tcp 8081
systemctl enable --now httpd

# 8.3 Register the source inside Fleet so upgrades use http://$HOST_IP:8081/downloads/
HOST_IP=$(hostname -I | awk '{print $1}')
curl -s "http://$HOST_IP:8081/downloads/beats/elastic-agent/" >/dev/null

echo ">>> Registering Local Repo in Fleet..."
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X POST \
  "https://localhost:5601/api/fleet/agent_download_sources" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d "{\"name\": \"Local Repo\", \"host\": \"http://$HOST_IP:8081/downloads/\", \"is_default\": true}"

echo ">>> Repo online. Fleet upgrades now pull from http://$HOST_IP:8081"

# ======================================================
# 9. HOW TO UPDATE (Copy new tarballs to Archive first!)
# ======================================================
# To update, change the versions at the top of this file, then run these blocks:

echo ">>> 1. STOPPING SERVICES..."
systemctl stop elasticsearch kibana elastic-agent

echo ">>> 2. EXTRACTING NEW VERSIONS..."
# (Run the 'Extract Archives' block above with new versions set)
# Or manually here:
# tar -xzf "$SRC_ARCHIVE/elasticsearch-$ES_VER-linux-x86_64.tar.gz" -C "$BASE_DIR/elasticsearch/$ES_VER" --strip-components=1
# tar -xzf "$SRC_ARCHIVE/kibana-$KB_VER-linux-x86_64.tar.gz" -C "$BASE_DIR/kibana/$KB_VER" --strip-components=1
# tar -xzf "$SRC_ARCHIVE/elastic-agent-$AGENT_VER-linux-x86_64.tar.gz" -C "$BASE_DIR/elastic-agent/$AGENT_VER" --strip-components=1

echo ">>> 3. UPDATING SYMLINKS (The Switch)..."
ln -sfn "$BASE_DIR/elasticsearch/$ES_VER" "$BASE_DIR/elasticsearch/current"
ln -sfn "$BASE_DIR/kibana/$KB_VER" "$BASE_DIR/kibana/current"
ln -sfn "$BASE_DIR/elastic-agent/$AGENT_VER" "$BASE_DIR/elastic-agent/current"

echo ">>> 4. FIXING PERMISSIONS..."
chown -R elastic:elastic "$BASE_DIR"

echo ">>> 5. STARTING SERVICES..."
systemctl start elasticsearch kibana elastic-agent

echo ">>> Update Complete! Check status:"
systemctl status elasticsearch kibana elastic-agent --no-pager
chown -R elastic:elastic "$REPO_DIR"

echo ">>> Setup Complete!"
echo "    Stack is running."
echo "    To update: Drop files in $REPO_DIR/incoming and run $REPO_DIR/update_stack.sh"


# ======================================================
# Appendix A - VM Reset Recovery (2025-12-07)
# ======================================================
# Context: Stack did not auto-start after a VM reset. Services are enabled and confirmed running.
# Actions performed:
#   - Checked service state: systemctl status elasticsearch kibana elastic-agent --no-pager
#   - Reloaded units and ensured enablement/autostart: systemctl daemon-reload && systemctl enable --now elasticsearch kibana elastic-agent
#   - Verified healthy state (all active): systemctl status elasticsearch kibana elastic-agent --no-pager
#
# Keep-it-fixed checks after any reboot/reset:
#   1) systemctl status elasticsearch kibana elastic-agent --no-pager
#   2) ss -tlnp | grep -E '9200|5601|8220'
#   3) curl -k https://localhost:9200 -u elastic:<pwd> ; curl -k https://localhost:8220/api/status | head -1
#   4) If a service is inactive: systemctl restart <service>; if masked/disabled: systemctl enable --now <service>
#   5) Validate symlinks: ls -l /opt/elastic/elasticsearch/current /opt/elastic/kibana/current /opt/elastic/elastic-agent/current
# Notes:
#   - Units are already enabled; they should start on boot. Use journalctl -u <service> -b for boot-time errors.
#   - If elastic-agent fails after upgrade, re-run the Fleet install block with a fresh tarball (integrity matters).

# ======================================================
# Appendix B - Service Visibility Fix (2025-12-07)
# ======================================================
# Issue: User reported Kibana/ES not visible after refresh; wanted confirmation and fix.
# Actions now:
#   - Checked services: systemctl status elasticsearch kibana elastic-agent --no-pager (ES/Agent were active).
#   - Restarted Kibana to clear stale state and confirm clean start:
#         systemctl restart kibana
#         systemctl status kibana --no-pager
#   - Result: Kibana active (PID shown) and Elasticsearch already running.
#
# If UI is not reachable:
#   - Confirm ports: ss -tlnp | grep -E '9200|5601|8220'
#   - Check Kibana logs: journalctl -u kibana -n 200 --no-pager
#   - If Kibana cannot reach ES, ensure ES is up and credentials/certs are correct.
#   - Restart order tip: systemctl restart elasticsearch kibana elastic-agent (ES first).

# ======================================================
# Appendix C - Elasticsearch/Kibana Recovery (2025-12-07)
# ======================================================
# Symptom: UI still blank; Elasticsearch not serving 9200 and Kibana failing auth.
# Root causes found:
#   - /opt/elastic/elasticsearch/current/config/service_tokens owned by root (AccessDenied on boot).
#   - Kibana keystore owned by root; kibana_system password mismatch/unknown.
#
# Fix steps performed:
#   1) Fix ES service_tokens ownership and restart ES:
#        chown elastic:elastic /opt/elastic/elasticsearch/current/config/service_tokens
#        systemctl restart elasticsearch
#   2) Reset built-in passwords:
#        su elastic -c "/opt/elastic/elasticsearch/current/bin/elasticsearch-reset-password -u elastic -b"
#        su elastic -c "/opt/elastic/elasticsearch/current/bin/elasticsearch-reset-password -u kibana_system -b"
#      (Captured new values; update below.)
#   3) Fix Kibana keystore ownership and set kibana_system password:
#        chown elastic:elastic /opt/elastic/kibana/current/config/kibana.keystore
#        su elastic -c "/opt/elastic/kibana/current/bin/kibana-keystore remove elasticsearch.password"
#        echo '<kibana_system_password>' | su elastic -c "/opt/elastic/kibana/current/bin/kibana-keystore add elasticsearch.password -x"
#   4) Restart Kibana:
#        systemctl restart kibana
#   5) Verify:
#        ss -tlnp 'sport = :9200'   # java PID listening
#        curl -k https://localhost:9200 -u elastic:<elastic_password>
#        systemctl status elasticsearch kibana elastic-agent --no-pager
#
# Current creds (set by codex on 2025-12-07):
#   elastic: 3BO3gA2Uh1sW5JwDHOh0
#   kibana_system: sgey+v4Q6GwW+FOUVrEe
#
# Notes to keep it fixed:
#   - Ensure ES/Kibana keystores and service_tokens are owned by elastic:elastic.
#   - After reboots, if Kibana shows auth errors, re-run the keystore password set and restart Kibana.
#   - If curl to https://localhost:9200 fails with bad_certificate, re-check the keystore password alignment and CA paths.

# ======================================================
# Appendix D - Kibana Visibility Check (2025-12-07)
# ======================================================
# Kibana is up and redirecting to login (HTTP 302 to /login) on HTTPS 5601. 
# Tested:
#   curl -k -I https://localhost:5601   # returns 302 /login
#   curl -k https://localhost:9200 -u elastic:3BO3gA2Uh1sW5JwDHOh0  # returns cluster info
#
# If the browser shows blank/blocked:
#   - Use https://<HOST_IP>:5601 (not http). Browser may warn on self-signed cert; accept/advance.
#   - Import the CA used for Kibana: /opt/elastic/elastic-certs/elasticsearch/http_ca.crt into browser trust, then reload.
#   - Credentials: elastic / 3BO3gA2Uh1sW5JwDHOh0
#   - If login fails, re-set kibana_system password in the Kibana keystore (steps in Appendix C) and restart Kibana.
#   - Check port: ss -tlnp | grep 5601 ; check logs: journalctl -u kibana -n 200 --no-pager

# ======================================================
# Appendix E - Elasticsearch Auto-Recovery Hardening (2025-12-13)
# ======================================================
# GOAL: Ensure the elasticsearch.service unit automatically recovers if ES exits, stalls during stop,
#       or the VM reboots unexpectedly.
#
# --- E.1 Update /etc/systemd/system/elasticsearch.service ---
# Use the existing block from section 5 as-is, then append these directives (or edit the existing ones):
cat <<'EOF' > /etc/systemd/system/elasticsearch.service
[Unit]
Description=Elasticsearch
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=elastic
Group=elastic
WorkingDirectory=/opt/elastic/elasticsearch/current
ExecStart=/opt/elastic/elasticsearch/current/bin/elasticsearch
LimitNOFILE=65535
TimeoutStopSec=90          # allow JVM to flush/stop cleanly before systemd kills it
Restart=always             # critical: auto-restart on crash or failure
RestartSec=10              # short backoff so we do not hammer the node on repeated failures

[Install]
WantedBy=multi-user.target
EOF

# --- E.2 Apply & Verify ---
systemctl daemon-reload
systemctl restart elasticsearch
systemctl status elasticsearch --no-pager

# Expected status: "active (running)". If the node was previously hung, systemd now waits longer on stop
# (TimeoutStopSec=90) and immediately restarts the JVM when it fails (Restart=always).

# --- E.3 Health Check ---
curl --silent --cacert /opt/elastic/elasticsearch/current/config/certs/http_ca.crt \
  -u elastic:$(awk -F= '/^elastic=/{print $2}' /opt/elastic/passwords.txt) \
  https://localhost:9200/_cluster/health?pretty

# Sample output after a clean restart:
#   "status" : "yellow",
#   "active_primary_shards" : 45,
#   "unassigned_shards" : 3
#
# Yellow is expected immediately after restart with 3 replica shards unassigned (single-node lab). 
# If the curl fails, re-check that elasticsearch.service is running and that /opt/elastic/elasticsearch/current/config/certs/http_ca.crt exists.

# --- E.4 Boot Persistence ---
systemctl is-enabled elasticsearch   # should return "enabled"
systemctl list-jobs | grep elasticsearch || echo "no pending restart jobs"

# --- E.5 Failure Simulation (optional but recommended) ---
# pkill -9 -u elastic -f elasticsearch
# sleep 10
# systemctl status elasticsearch --no-pager   # should show systemd restarted it automatically
# journalctl -u elasticsearch -n 20 --no-pager

# Notes:
#   - StartLimitIntervalSec / StartLimitBurst prevents systemd from giving up after multiple failures.
#   - TimeoutStopSec increased from 20 -> 90 so index writes finish before SIGKILL.
#   - RestartSec avoids thrashing the ecosystem if ES is crash-looping because of configuration errors; see logs.

# ======================================================
# Appendix F - Rebuild Bundle & Fleet Policy Imports (2025-12-13)
# ======================================================
# GOAL: Keep the golden `/opt/archive/rebuild-bundle` artifacts wired into the standard run book so every redeploy
#       reuses the proven Fleet agent policies, scripts, and dashboards (with agent metrics enabled everywhere).
#
# --- F.1 WHERE EVERYTHING LIVES ---
#   /opt/archive/rebuild-bundle/
#       README.md                       # quick overview
#       docs/deployment-guide.md        # full-stack rebuild steps (Linux & Windows)
#       docs/baseline-runbook.md        # packet-capture/baseline notes
#       policies/*.json                 # Fleet agent policies to import (see below)
#       scripts/deploy-linux.sh         # automate agent install/enroll (uses POLICY_ID + token)
#       scripts/deploy-windows.ps1      # Windows equivalent (Npcap optional)
#       kibana/network-baseline-dashboard.ndjson   # Saved objects bundle
#       stack-config/*                  # Known-good elasticsearch.yml / kibana.yml / certs
#
# Copy to another host if needed:
#   cd /opt/archive && tar -czf rebuild-bundle.tar.gz rebuild-bundle
#
# --- F.2 ENSURE FLEET COLLECTS AGENT METRICS (LOGS + METRICS) ---
# Fleet UI path: Kibana > Fleet > Settings > Agent monitoring -> enable both "Collect agent logs" and "Collect agent metrics".
# CLI/API option (set once per policy to guarantee metrics are shipped for dashboards):
#   export ELASTIC_PASS=$(awk -F= '/^elastic=/{print $2}' /opt/elastic/passwords.txt)
#   POLICY_ID=<policy_id_here>
#   curl -s -k -u "elastic:${ELASTIC_PASS}" \
#     -X PUT "https://localhost:5601/api/fleet/agent_policies/${POLICY_ID}" \
#     -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
#     -d "{\"name\":\"<policy_name>\",\"namespace\":\"default\",\"description\":\"<desc>\",\"monitoring_enabled\":[\"logs\",\"metrics\"]}"
# Run that for every agent policy (Fleet Server, Linux, Windows, NetFlow, VMware) so the central Fleet dashboards get host + agent telemetry.
#
# --- F.3 IMPORT THE BASELINE POLICIES ---
# Kibana workflow (preferred):
#   1. Kibana > Fleet > Agent policies > Create agent policy > switch to "Import policy" and upload the JSON from /opt/archive/rebuild-bundle/policies/.
#   2. Repeat for each JSON listed below; after import, open the policy and create at least one enrollment token per deployment tier.
#   3. Confirm each policy shows "Agent monitoring: Logs & Metrics".
#
# API workflow (air-gapped automation):
#   - POST /api/fleet/agent_policies?sys_monitoring=true with the `.policy` block from each JSON (add monitoring_enabled=["logs","metrics"]).
#   - Then POST /api/fleet/package_policies for every object in `.package_policies[]` (system, auditd, windows, syslog, netflow, vmware).
#   - The JSON files in rebuild-bundle already contain the correct `inputs[].streams[].vars`; only inject the target `policy_id` returned by the first call.
#
# --- F.4 WHAT EACH POLICY DOES ---
# 1. linux-network-baseline.json
#    - Integrations: system (socket + process metrics), auditd (network syscall rules), filestream (auth + firewall logs).
#    - Ports/reqs: auditd enabled, /var/log/auth.log + /var/log/secure readable, SELinux permissive or policy for auditd.
#    - Use scripts/deploy-linux.sh with POLICY_ID from Fleet and enrollment token tied to this policy.
#
# 2. windows-network-baseline.json
#    - Integrations: system (socket/process metrics), windows (Security, Firewall, DNS client), network_traffic (pcap-lite DNS/HTTP/TLS/ICMP).
#    - Requires Windows Event Logging enabled, optional `${CAPTURE_INTERFACE}` variable in Fleet for packet capture binding.
#    - Use scripts/deploy-windows.ps1 (Npcap recommended) with Fleet enrollment token for this policy.
#
# 3. netflow-syslog-collector.json
#    - Integrations: netflow (UDP 2055/4739/6343 listeners), syslog (TCP+TLS/UDP 1514) with TLS cert/key at /etc/pki/tls/{certs,private}.
#    - Target: small Linux VM in DMZ aggregating network hardware telemetry. Ensure firewall opens UDP/TCP ports before enrollment.
#
# 4. vmware-vsphere.json
#    - Integrations: vmware (vsphere metrics) + syslog (ESXi UDP 1515). Fleet secrets for ${VCENTER_USERNAME}/${VCENTER_PASSWORD}.
#    - Configure ESXi hosts to forward syslog to udp://<collector>:1515 and set VCENTER_* variables in the policy before enrollment.
#
# Post-import checklist:
#   - Generate an enrollment token for each policy (Fleet > Agent policies > <policy> > Enrollment tokens).
#   - Distribute /opt/archive/rebuild-bundle/scripts/deploy-*.{sh,ps1} alongside elastic-agent artifact + http_ca.crt.
#   - Verify new agents show under Fleet with Policy Name matching the baseline, and that the "Agent monitoring" column shows logs+metrics.
#
# --- F.5 DASHBOARDS / SAVED OBJECTS ---
#   - Import /opt/archive/rebuild-bundle/kibana/network-baseline-dashboard.ndjson via Kibana > Stack Management > Saved Objects > Import.
#   - Set the default data view to "logs-*" and load the "Network Baseline" dashboard to confirm socket/process/auth feeds are present.
#   - If dashboards show empty panels, confirm the policies above are running and shipping metrics (Fleet > Agents > select agent > Logs/Metrics tab).
#
# --- F.6 FIELD NOTES ---
#   - When cloning the bundle to another host, re-run the certificate commands (Section 3) or update Fleet CA fingerprints accordingly.
#   - The same JSONs work on upgrades; update paths under rebuild-bundle if you bump packages (e.g., edit `version` from "latest" to a pinned build).
#   - Keep `/opt/archive/rebuild-bundle/docs/deployment-guide.md` nearby; it captures the full redeploy + Fleet bootstrap flow tested in this lab.

# ======================================================
# Appendix G - Fleet Server HTTPS Output Fix (2025-12-13)
# ======================================================
# Symptom: Fleet UI banner “Fleet Server is not Healthy.” Agents attempted to talk HTTP->Elasticsearch even though ES/Kibana only
#          allow HTTPS, so Fleet Server output checks failed.
#
# --- G.1 Calculate the CA fingerprint once ---
#   FINGERPRINT=$(openssl x509 -fingerprint -sha256 -noout \
#                  -in /opt/elastic/elasticsearch/current/config/certs/http_ca.crt \
#                  | tr -d ':' | cut -d'=' -f2)
#   echo "$FINGERPRINT"
#
# --- G.2 Force the default Fleet output to HTTPS with the fingerprint ---
#       (Use the LAN IP so remote Windows hosts never attempt to send data to https://localhost:9200.)
#   curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
#     -X PUT "https://localhost:5601/api/fleet/outputs/fleet-default-output" \
#     -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
#     -d "{\"name\":\"default\",\"type\":\"elasticsearch\",\"is_default\":true,\"is_default_monitoring\":true,\
#          \"hosts\":[\"https://192.168.1.164:9200\"],\
#          \"config_yaml\":\"ssl:\\n  ca_trusted_fingerprint: ${FINGERPRINT}\"}"
# This keeps both data + monitoring outputs on HTTPS and tells Elastic Agent to trust the bundled CA without copying files around.
#
# --- G.3 Confirm Fleet Server host URLs stay on HTTPS/8220 ---
#   curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" https://localhost:5601/api/fleet/fleet_server_hosts \
#     | jq '.items[] | {name, host_urls}'
# Expected host URL: https://<host_ip>:8220 (already set earlier, but verify after redeploys).
#
# --- G.4 Restart Elastic Agent so it picks up the new output ---
#   systemctl restart elastic-agent
#   /opt/Elastic/Agent/elastic-agent status        # should show fleet + elastic-agent healthy within ~30s
#
# --- G.5 Health checks (CLI) ---
#   curl -s -k https://localhost:8220/api/status            # => {"status":"HEALTHY"}
#   curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" https://localhost:5601/api/fleet/agents?perPage=1 \
#       | jq '.items[0] | {id,last_checkin_status,components}'
# Look for `last_checkin_status: "online"` and component messages “Running on policy with Fleet Server integration...”.
#
# --- G.6 Health checks (UI) ---
#   - Kibana > Fleet > Agents should clear the yellow banner after the next check-in (< 1 min).
#   - The Fleet Server entry should show Status = Healthy, Last activity timestamps updating, and “Agent monitoring: Logs & Metrics”.
#
# Notes:
#   - If the banner reappears later, re-run STEP G.2 to ensure outputs still reference HTTPS (Fleet upgrades sometimes revert to http://).
#   - Use `journalctl -u elastic-agent -n 200 --no-pager` if Fleet Server stays in STARTING > 2 min; most issues are missing fingerprint or wrong host URL.
#   - When cloning to another VM, regenerate the CA cert or recalc the fingerprint and repeat STEP G.2 before enrolling any agents.

# ======================================================
# Appendix H - Legacy Fleet Server Setup (Claude Opus 4.5 - Verified)
# ======================================================
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                                                                              ║
# ║   ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗     ██████╗ ██████╗       ║
# ║  ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝    ██╔═══██╗██╔══██╗      ║
# ║  ██║     ██║     ███████║██║   ██║██║  ██║█████╗      ██║   ██║██████╔╝      ║
# ║  ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝      ██║   ██║██╔═══╝       ║
# ║  ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗    ╚██████╔╝██║           ║
# ║   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝     ╚═════╝ ╚═╝           ║
# ║                                                                              ║
# ║              FLEET SERVER SETUP - VERIFIED WORKING COMMANDS                  ║
# ║                           Date: 2025-12-07                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# These commands were debugged and verified working by Claude Opus 4.5.
# The key lesson: Download from elastic.co was getting truncated. A fresh, complete
# tarball (444MB) was required for the binary to work.
#
# Prerequisites: ES and Kibana must be running.
# Generate a service token in Kibana: Fleet > Settings > Service Token

# --- H.1 VARIABLES ---
# Get these from Kibana Fleet Settings
FLEET_SERVICE_TOKEN="<YOUR_TOKEN_FROM_KIBANA>"
HOST_IP=$(hostname -I | awk '{print $1}')

# --- H.2 CLEAN INSTALL ---
# Remove any previous failed attempts
rm -rf /opt/Elastic/Agent
rm -rf /etc/systemd/system/elastic-agent.service
systemctl daemon-reload

# --- H.3 EXTRACT FRESH TARBALL ---
# IMPORTANT: Tarball MUST be complete (444MB+ for agent 9.2.2)
rm -rf "$BASE_DIR/elastic-agent/$AGENT_VER"
mkdir -p "$BASE_DIR/elastic-agent/$AGENT_VER"
tar -xzf "$SRC_ARCHIVE/elastic-agent-$AGENT_VER-linux-x86_64.tar.gz" \
    -C "$BASE_DIR/elastic-agent/$AGENT_VER" --strip-components=1

# --- H.4 INSTALL FLEET SERVER ---
cd "$BASE_DIR/elastic-agent/current"
./elastic-agent install \
  --fleet-server-es="https://$HOST_IP:9200" \
  --fleet-server-service-token="$FLEET_SERVICE_TOKEN" \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca="$BASE_DIR/kibana/current/config/certs/http_ca.crt" \
  --fleet-server-port=8220

# --- H.5 CREATE SYSTEMD SERVICE (if not auto-created) ---
cat > /etc/systemd/system/elastic-agent.service <<'EOSVC'
[Unit]
Description=Elastic Agent - Fleet Server
After=network.target elasticsearch.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/Elastic/Agent/elastic-agent run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOSVC

systemctl daemon-reload
systemctl enable --now elastic-agent

# --- H.6 FIX FLEET SERVER HOST URL (CRITICAL!) ---
# The install sets Fleet Server host to port 9200 by default - WRONG!
# It must be 8220 (the actual Fleet Server port)
echo ">>> Fixing Fleet Server host URL in Kibana..."

# Get the Fleet Server host ID
FLEET_HOST_ID=$(curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" \
  "https://localhost:5601/api/fleet/fleet_server_hosts" \
  -H 'kbn-xsrf: true' | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

# Update to correct port 8220
curl -s -k -u "elastic:${ELASTIC_BOOT_PWD}" -X PUT \
  "https://localhost:5601/api/fleet/fleet_server_hosts/$FLEET_HOST_ID" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d "{\"name\": \"fleet-policy\", \"host_urls\": [\"https://$HOST_IP:8220\"], \"is_default\": true}"

# Restart agent to pick up new config
systemctl restart elastic-agent
sleep 15

# --- H.7 VERIFY ---
echo ">>> Checking Fleet Server..."
systemctl status elastic-agent --no-pager | head -10
ss -tlnp | grep 8220
curl -s -k https://localhost:8220/api/status | head -1
/opt/Elastic/Agent/elastic-agent status | head -5

# --- H.8 UNINSTALL (if needed) ---
# /opt/Elastic/Agent/elastic-agent uninstall --force

# LESSONS LEARNED (Claude Opus 4.5):
# 1. TARBALL INTEGRITY: Always verify tarball is complete (444MB+ for agent).
# 2. FLEET HOST URL: After install, Fleet Server host URL defaults to wrong port (9200); change to 8220.
# 3. ES OUTPUT: Default ES output uses HTTP - switch to HTTPS or use Appendix G fingerprint method.
# 4. SYSTEMD SERVICE: The install may not create a systemd service; create one manually if missing.
# 5. VERIFICATION ORDER:
#    - systemctl status elastic-agent  (service running?)
#    - ss -tlnp | grep 8220            (port listening?)
#    - curl https://localhost:8220/api/status  (API responding?)
#    - /opt/Elastic/Agent/elastic-agent status  (components healthy?)
