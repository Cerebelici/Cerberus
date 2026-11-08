# Cerberus (Network Sentinel & Endpoint Observability)

Cerberus is an automated cybersecurity intelligence platform combining **active network sweeps** with **Linux kernel-level endpoint observability**. 

It bridges the visibility gap between external network vulnerability scanning and internal runtime behavior:
- **Cerberus Sentinel (`cerberus`)**: A Go daemon that actively discovers subnet hosts via Nmap, audits open services and CVEs (using `vulners.nse`), tracks host availability lifecycles over a continuous timeline, ingests endpoint telemetry, correlates real-time attack patterns (MITRE ATT&CK), and computes unified fleet posture scores.
- **Cerberus Agent (`cerberus-agent`)**: A lightweight eBPF security probe written in C (`libbpf` CO-RE) that instruments kernel tracepoints and uprobes to capture process executions, outbound network connections, interactive bash readline commands, memory injections, file tampering, and privilege escalations, streaming batched telemetry to the Sentinel over authenticated HTTP/JSON.
- **Desktop Packaging**: A standalone Linux desktop application built with Wails v2 that hosts the Go Sentinel daemon in the background while keeping the ingestion port open for remote agents.

---

## Key Capabilities

- **Automated Network Sweeps & CVE Auditing**: Periodic discovery sweeps (every 30 min) and service vulnerability audits (every 10 min) with instant reactive scanning whenever a new host joins the network.
- **In-Kernel Endpoint Observability**: Kernel eBPF hooks on process executions, IPv4/IPv6 socket connections, bash commands, `process_vm_writev` memory injections, ptrace, and sensitive file tampering with in-kernel noise filtering.
- **Real-Time Threat Detection (IRT Engine)**: 10 deterministic security rules mapped to MITRE ATT&CK tactics and techniques, detecting reverse shells, webshells, cross-process injections, fileless executions, and root privilege escalations.
- **Temporal Activity Timeline**: Segmented device availability and security posture tracking over time (`/api/timeline`) with carry-in state reconstruction and gap-free intervals.
- **3-Tier Device Identification & Reconciliation**: Recognizes returning devices across dynamic DHCP IP changes and randomized Wi-Fi MAC addresses using digital service keys, per-Wi-Fi MAC persistence, and post-scan service matching.
- **Fleet Security Posture (`cvss-agg-v1`)**: Deterministic scoring formula aggregating host CVSS scores with active exploit bonuses and deducting penalties for recent live incidents into a unified 0.0–100.0 fleet rating.

---

## How Cerberus Identifies Devices (3-Tier Identity Engine)

In modern networks, a device's IP address can change whenever it reconnects (via DHCP), and phones or laptops often hide their real hardware MAC address using privacy randomization. To avoid creating duplicate records for the same device, Cerberus identifies devices in **three simple steps** (like checking a passport first, then a visitor badge, and finally a physical description):

| Tier | Everyday Analogy | What Cerberus Checks | When It Is Used |
|---|---|---|---|
| **Tier 1: Digital Passport** | Checking a passport ID number | Permanent digital keys and IDs that never change when IP or MAC changes: `cerberus-agent` ID, SSH server keys (`ssh-hostkey`), HTTPS/SSL certificates (`ssl-cert`), or UPnP/SMB device UUIDs. | Gives **100% certainty** for managed Linux machines, servers, routers, printers, and smart devices—even if both IP and MAC change. |
| **Tier 2: Hardware & Per-Wi-Fi MAC** | Checking a building visitor badge | Real factory MAC addresses (for wired PCs, servers, IoT) **or** the per-Wi-Fi private MAC address that modern phones and laptops (iOS, Android, Windows, macOS) reuse on the same Wi-Fi network. | Immediately recognizes phones, laptops, and wired devices during the fast discovery scan (`-sn`) whenever the router gives them a **new IP address**. |
| **Tier 3: Post-Scan Service & Name Match** | Recognizing someone by their name and profile | Local DNS hostname combined with the list of open ports/services discovered after the port scan (`-sV`) finishes. | Catches devices that changed **both** their IP and MAC address at the same time, and automatically merges any temporary discovery record back into the original device. |

### How the Two-Step Scan Works Together
1. **Step 1 — Fast Discovery (`RunDiscoveryScan`, `-sn`)**: Cerberus quickly checks which IP addresses are online and resolves their local hostnames. If a device matches **Tier 1** (active agent) or **Tier 2** (same hardware MAC or same per-Wi-Fi private MAC on a new IP), Cerberus immediately links it to the existing device. If the IP and MAC are both completely unfamiliar, Cerberus creates a temporary record and triggers an immediate port scan.
2. **Step 2 — Deep Service & Key Check (`RunVulnerabilityScan`, `-sV`)**: Cerberus scans the device's open ports, security vulnerabilities, and digital keys (SSH keys, SSL certificates). Once this scan finishes, Cerberus re-checks the device against offline history: if its digital keys (**Tier 1**) or its hostname + open ports (**Tier 3**) match an earlier device, Cerberus automatically merges the temporary record into the original device so all timeline history and alerts stay in one place.

### Built-In Safeguards Against Duplicate Devices
- **Ignoring Ghost Hosts in Unprivileged Mode (`-Pn`)**: When running without raw-socket privileges (`CERBERUS_UNPRIVILEGED=true`), Nmap uses `-Pn`, which reports every scanned IP as "online" even if no device is actually listening there. Cerberus filters out any `-Pn` result that has both zero open ports and no MAC address *before* running identity matching, so inactive or non-responsive IPs never create phantom device records.
- **Handling Scans Without MAC Addresses**: When Nmap scans across a network where MAC addresses aren't visible (such as unprivileged TCP scans or local container interfaces), Cerberus keeps linking the scan result to the active device holding that IP lease (`IPLease + IPOnlyLease`) rather than creating a new device on every scan. The same applies when a device recorded without a MAC is seen with one for the first time. Empty IP-only records never compete with a device that holds the same IP lease; binding merges them into it.
- **MAC Addresses from the ARP Table (macOS)**: macOS always scans with unprivileged TCP connect, which cannot read MAC addresses and misses hosts that drop every probed port (phones, many IoT devices). After each sweep, Cerberus reads the ARP entries the OS confirmed during the sweep (`arp -anx`, entries with a running timer only): it fills the MAC of every found host and adds hosts that answered ARP but no TCP probe. Vendors come from the `nmap-mac-prefixes` database installed with nmap.
- **One Active Device Per IP**: Cerberus deduplicates target IPs before every scan and automatically marks any older device record at the same IP as `down` when a new device takes over that address, preventing duplicate entries from accumulating.

---

## Deployment & Launch Guides

Cerberus supports two primary deployment topologies:

```
[ Deployment Scenarios ]
1. Distributed VMs + Tailscale-> Overlay mesh VPN connecting Sentinel to remote Linux VMs
2. Real Physical Network      -> Host LAN sweeps (Wi-Fi/Ethernet) + physical Linux server probes
```

---

### Scenario 1: Distributed Setup across VMs using Tailscale

Best for multi-node labs, hybrid environments, or cloud VMs across different clouds/VPCs without requiring port forwarding or public IP exposure.

```
+-----------------------------------------------------------------------------------+
|                            TAILSCALE OVERLAY NETWORK                              |
|                                                                                   |
|  [Sentinel Host / VM]                      [Target VM 1]          [Target VM 2]   |
|  Tailscale IP: 100.64.0.1                  100.64.0.10            100.64.0.20     |
|  - Go Sentinel Daemon (:8080)              - cerberus-agent       - cerberus-agent|
|  - Discovers Tailscale mesh                - eBPF monitoring      - eBPF          |
|  - Ingests agent telemetry <----------------- HTTPS Batches --------+             |
+-----------------------------------------------------------------------------------+
```

#### Step 1: Join Hosts to Tailscale
Install and authenticate Tailscale on the Sentinel machine and all target Linux VMs:
```bash
sudo tailscale up
```
Note the assigned Tailscale IPs (e.g., `100.64.0.1` for Sentinel, `100.64.0.10` for VM 1) or MagicDNS hostnames.

#### Step 2: Start the Sentinel on the Tailscale Interface
Run the Sentinel configured with a shared enrollment secret and targeting your Tailscale subnet or LAN:
```bash
# Set shared enrollment secret and bind to all interfaces (or your tailscale IP)
export CERBERUS_PORT=8080
export CERBERUS_HOST=0.0.0.0
export CERBERUS_ENROLL_TOKEN="cerberus-secret-token"
export CERBERUS_SUBNET="100.64.0.0/24"  # Sweep specific Tailscale IP range or local subnet

./bin/sentinel
```

#### Step 3: Install & Start Cerberus Agent on Target VMs
On each remote Linux VM (Ubuntu, Debian, Fedora with kernel $\ge 5.8$):
```bash
# 1. Clone repository and install eBPF build toolchain
git clone https://github.com/gr0gu/cerberus-agent.git
cd cerberus-agent
sudo ./setup.sh

# 2. Compile kernel bytecode and userspace binary
make clean && make

# 3. Launch agent pointing to Sentinel's Tailscale IP
sudo ./proc_exec \
  --sentinel-url "http://100.64.0.1:8080" \
  --enroll-token "cerberus-secret-token" \
  --insecure-http
```
*Note: The agent automatically performs initial enrollment, receives a secure bearer token, discovers local network interfaces, and streams eBPF telemetry batches across the encrypted Tailscale tunnel.*

---

### Scenario 2: Real Physical Devices in a Real Network (LAN / Wi-Fi)

Best for home labs, office subnets, or dedicated security appliance deployments monitoring physical workstations, IoT devices, printers, and servers.

```
+-----------------------------------------------------------------------------------+
|                        PHYSICAL LOCAL NETWORK (192.168.1.0/24)                    |
|                                                                                   |
|  [Sentinel Appliance]           [Physical Server]            [Unmanaged Devices]  |
|  IP: 192.168.1.5                IP: 192.168.1.50             IP: 192.168.1.100+   |
|  - Sweeps 192.168.1.0/24        - Ubuntu Server              - Smart TVs, Printers|
|  - Ingestion Listener           - cerberus-agent installed   - Laptops, Phones    |
|  - Identity Reconciliation <------ Real-time telemetry        - Scanned via Nmap  |
+-----------------------------------------------------------------------------------+
```

#### Step 1: Prepare Raw Socket Capabilities on Sentinel Host
To enable fast ARP, ICMP, and OS detection sweeps without running the Sentinel binary as `root`:
```bash
# Grant raw packet capture capabilities directly to the Nmap binary
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```
*If unprivileged, Cerberus automatically falls back to TCP connect sweeps (`-sT -Pn -PS/PA`).*

#### Step 2: Configure Sentinel for Your Physical Subnet
Identify your local subnet (e.g., via `ip route | grep default` or `ip addr`) and launch Sentinel:
```bash
export CERBERUS_SUBNET="192.168.1.0/24"       # Your local network CIDR
export CERBERUS_PORT=8080
export CERBERUS_ENROLL_TOKEN="prod-corp-secret"
export CERBERUS_UNPRIVILEGED=false            # Uses raw socket capabilities

./bin/sentinel
```
*Or launch the desktop UI via `wails dev` or the compiled desktop app.*

#### Step 3: Deploy Agents to Critical Linux Endpoints
On your physical Linux servers, workstations, or Raspberry Pis:
```bash
cd cerberus-agent
make clean && make

sudo ./proc_exec \
  --sentinel-url "http://192.168.1.5:8080" \
  --enroll-token "prod-corp-secret" \
  --insecure-http \
  --auto-kill   # Optional: automatically terminates CRITICAL threats locally
```

#### Step 4: Asset Reconciliation in Action
- **Unmanaged Devices** (phones, printers, smart TVs): Sentinel tracks them via digital service keys (SSH/TLS/UPnP), per-Wi-Fi MAC persistence, open port profiles, and DHCP lease history.
- **Managed Endpoints**: The agent self-reports its network interfaces and machine UUID. When Sentinel sweeps the LAN, the Identity Matcher correlates wire observations with internal agent telemetry.

---

## Configuration Reference

Key settings can be configured via environment variables:

| Variable | Description | Default |
|---|---|---|
| `CERBERUS_PORT` | HTTP server port for REST API and agent ingestion | `8080` |
| `CERBERUS_HOST` | Network interface to bind | `0.0.0.0` |
| `CERBERUS_DB_PATH` | Path to SQLite database file | `cerberus.db` |
| `CERBERUS_SUBNET` | Target CIDR to discover (e.g. `192.168.1.0/24`) | `172.28.0.0/24` |
| `CERBERUS_DISCOVERY_INTERVAL` | Network discovery scan frequency | `30m` |
| `CERBERUS_VULN_INTERVAL` | Vulnerability audit scan frequency | `10m` |
| `CERBERUS_ENROLL_TOKEN` | Pre-shared token required for agent enrollment | *Empty* |
| `CERBERUS_API_KEY` | Operator API key for administrative CRUD operations | *Empty* |
| `CERBERUS_UNPRIVILEGED` | Force unprivileged TCP connect scan fallback | `true` |
| `CERBERUS_SCAN_PORTS` | Port range or option for vulnerability audit (e.g. `1-10000`, `21,22,80,3000,6379,8080`, `--top-ports 2000`) | `--top-ports 2000` |
| `CERBERUS_IMMEDIATE_DELAY` | Cooldown grace period before scanning newly booted hosts | `3s` |
| `CERBERUS_SCAN_TIMEOUT` | Maximum execution timeout per scan job | `15m` |

---

## REST API Overview

All responses are formatted in JSON:

### Inventory & Device Management
- `GET /api/devices`: List all tracked devices (filters: `?status=up|down`, `?managed=true|false`, `?min_risk=7.0`).
- `GET /api/devices/{id}`: Detailed device metadata, open/resolved CVEs, services, and agent status.
- `PATCH /api/devices/{id}`: Update device label, owner, criticality, or notes.
- `POST /api/devices/{id}/merge`: Administratively merge two device records.
- `POST /api/devices/{id}/split`: Split an address lease into an independent record.
- `GET /api/devices/{id}/identity`: Review deterministic matching rationale and decision audit logs.

### Scans, Settings & Logs
- `GET /api/status`: Live counters, next scheduled runs and `is_discovery_running` / `is_vuln_running` (queued manual scans and the immediate audit of new hosts count as running).
- `GET /api/scans?limit=N`: Scan history, newest first. Scans that a previous process left unfinished are recorded as `failed` with an "interrupted" message at startup.
- `POST /api/scans/discovery/trigger`, `POST /api/scans/vulnerability/trigger`: Queue a manual scan. `202` `{"message","status":"running","scan_type"}` when queued, `409` `{"error","status":"conflict","scan_type"}` when a scan of that type is already running or queued, `503` when no scheduler is available. The desktop IPC methods `TriggerDiscovery` / `TriggerVulnerabilityScan` return the same bodies.
- `GET /api/settings`, `PUT /api/settings`: Read and change the scan target, ports, intervals and privilege mode. Changes apply at once, without a restart (`PUT` needs loopback or `X-API-Key`).
- `GET /api/logs`: Recent daemon log lines `{seq, timestamp, level, source, message}`. The desktop app also streams new lines as `cerberus:log` events.

### Vulnerabilities & Timeline
- `GET /api/services`: List detected network services across all hosts.
- `GET /api/vulnerabilities`: List detected CVE vulnerabilities (filter: `?severity=CRITICAL`).
- `GET /api/timeline`: Reconstructed temporal activity periods and scan ticks across a time window (`?from=&to=`).

### Incident Detection & Posture
- `GET /api/incidents`: Query live security alerts detected by the IRT rule engine.
- `GET /api/incidents/{id}`: Inspect specific alert with full syscall evidence list.
- `PATCH /api/incidents/{id}`: Update incident state (`open`, `acknowledged`, `closed`).
- `GET /api/posture`: Current fleet security rating and individual host risk scores.
- `GET /api/posture/history`: Historical fleet security rating snapshots.

### Agent Ingestion
- `POST /api/v1/agent/enroll`: Secure enrollment endpoint issuing agent bearer tokens.
- `POST /api/v1/agent/telemetry`: High-throughput ingestion endpoint for eBPF event batches.
- `GET /api/agents`: Enumerate registered endpoint probes and live heartbeat status.

---

## Building from Source

### Headless Daemon
```bash
# Build standalone CGO-free Sentinel binary
make build-headless
```

### Desktop Application (Wails v2)
Requires the Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0`) and nmap on the machine that runs the app.

macOS: initialize the `front` submodule, then build the universal app and `Cerberus-macOS-universal.dmg` in the repository root:
```bash
git submodule update --init --recursive
./build-macos.sh
```
On the first scan, macOS asks whether Cerberus Sentinel may find devices on the local network. Until you allow it, macOS blocks every connection to the LAN; the scan waits up to a minute for the answer and then fails with a message instead of reporting an empty network. You can change the answer later in System Settings > Privacy & Security > Local Network.

Linux (requires `libgtk-3-dev` and `libwebkit2gtk-4.1-dev`):
```bash
make build-desktop
```

### C/eBPF Agent
Requires Linux kernel $\ge 5.8$ with BTF support, `clang`, `llvm`, and `libbpf-dev`:
```bash
cd ../cerberus-agent
sudo ./setup.sh
make clean && make
```

### Testing & Verification
```bash
# Run Go unit & integration tests with race detection
go test -race -count=1 ./...

# Run agent automated verification harness against mock Sentinel
cd ../cerberus-agent
python3 tests/mock_sentinel.py --test
```
