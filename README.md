# Cerberus (Network Sentinel & Endpoint Observability)

Cerberus is a cross-platform cybersecurity intelligence platform that combines **active
network sweeps** with **Linux kernel-level endpoint observability**.

- **Cerberus Sentinel** — a Go daemon that discovers hosts, audits open services and
  CVEs with nmap and RustScan, tracks device identity over time, ingests endpoint
  telemetry, runs deterministic detection rules, and computes fleet posture scores.
- **Cerberus Agent** — a lightweight eBPF probe (separate `cerberus-agent` repository)
  that streams process, network, shell, injection, and file-tampering events in batches.
- **Cerberus Desktop** — a Wails v2 app that embeds the daemon and talks to it over
  Wails IPC. It targets macOS, Windows, and Linux.

The UI does **not** use HTTP. The only HTTP listener is a loopback-only agent ingest
endpoint (`127.0.0.1:8080`). See [`docs/ipc-api.md`](docs/ipc-api.md) for the desktop
IPC contract and [`openapi.yaml`](openapi.yaml) for the ingest API.

---

## Key Capabilities

- **One tri-stage scan pipeline** (`HybridEngine`): L2/ARP mapping, fast port
  discovery through RustScan or nmap, then a targeted nmap service/vulnerability audit
  against only the ports that are actually open.
- **Scheduled and reactive scanning**: one full subnet sweep at startup, then a cheap
  known-device check every 5 minutes; vulnerability audits run every 20 minutes, plus an
  immediate audit when a new host appears. New hosts between full sweeps are picked up
  passively from mDNS/SSDP announcements and the kernel neighbour table. All scan work is
  serialized through one gate so scans never overlap.
- **Full-port discovery**: an empty `scan_ports` means a full 1-65535 sweep, because IoT
  and embedded devices routinely listen on non-standard high ports. Ranges, explicit
  lists, and `--top-ports N` are still supported when explicitly configured.
- **Endpoint observability**: eBPF hooks for process execution, IPv4/IPv6 connections,
  interactive shell commands, memory injection, ptrace, and sensitive file writes.
- **Real-time threat detection**: deterministic rules mapped to MITRE ATT&CK, covering
  reverse shells, webshells, cross-process injection, fileless execution, and privilege
  escalation.
- **Temporal timeline**: device availability and posture periods reconstructed across a
  time window without gaps.
- **3-tier device identity**: digital keys (agent ID, SSH host keys, TLS certificates,
  UPnP/SMB UUIDs), hardware or per-Wi-Fi MAC, then hostname plus service profile.
- **Fleet posture (`cvss-agg-v1`)**: deterministic 0.0–100.0 rating from CVSS scores,
  exploit bonuses, and incident penalties.

---

## How Scanning Works

Every discovery and vulnerability scan goes through `internal/scanner.HybridEngine`:

1. **Stage 1 — L2 mapping.** An ARP sweep wakes sleeping devices and refreshes the
   kernel ARP cache. The platform provider reads the cache natively (sysctl on macOS,
   netlink on Linux, `GetIpNetTable2` on Windows). These neighbors fill in MAC addresses
   and add hosts that answer ARP but drop every probed port.
2. **Stage 2 — Port sweep.** RustScan scans the configured scope (all 65,535 TCP ports
   by default). If RustScan is unavailable, or the scope is an nmap-only option such as
   `--top-ports N`, nmap performs the port sweep instead.
3. **Stage 3 — Deep audit.** nmap runs `-sV` plus the configured vulnerability script
   only against the ports discovered in Stage 2, then Cerberus stores services,
   vulnerabilities, and identity observations.

Discovery uses nmap `-sn` plus the ARP merge. It does not sweep all ports.

Between full sweeps, the discovery worker runs a known-device check: it sends one UDP
datagram per known address to refresh the kernel neighbour cache, falls back to short TCP
handshakes for routed hosts, and merges mDNS/SSDP announcements from devices that
advertise themselves. This is deliberately not a DHCP sniff: DHCP snooping requires a
platform-specific raw capture path and is considered future work. A full sweep also runs
on manual request and when the target network changes.

### Privileges and platform prerequisites

Privileged execution is **mandatory**. Cerberus never falls back to nmap TCP connect mode
(`-sT`): a connect scan cannot see filtered ports or the link layer, and silently changes
the meaning of a result. If the user refuses the elevation prompt, the scanners stay idle
and the UI reports why.

| Platform | Requirement |
|---|---|
| macOS | `nmap` (bundled in the `.app`, or Homebrew), RustScan (bundled), and the `com.cerberus.helper` root helper installed through **SMJobBless**. Installation raises the native macOS authorization prompt, which supports Touch ID, Apple Watch, or the administrator password. The helper binary must live at `Contents/Library/LaunchServices/com.cerberus.helper` with embedded `__info_plist` and `__launchd_plist` sections. The first sweep also triggers the macOS Local Network prompt. |
| Linux | `nmap` with `cap_net_raw,cap_net_admin,cap_net_bind_service` or root; RustScan is bundled or read from `PATH`. |
| Windows | Run elevated. The desktop executable uses a `requireAdministrator` manifest, so Windows shows a UAC prompt at launch. **Npcap is required** for raw packet capture; there is no `-sT` fallback. The portable nmap and RustScan binaries are bundled under `tools/`. |

If nmap is missing or below 7.80, startup reports the problem and the UI shows an
actionable capability warning. Scans do not run until the prerequisite is fixed and the
process is privileged. The headless daemon can still be run to inspect the database.

**macOS release builds must be signed with a Developer ID.** Local ad-hoc builds use the
bare `identifier` form and can install the helper for development (the app's
`CFBundleIdentifier` must match the helper's `SMAuthorizedClients`, and the helper's
identifier must match the app's `SMPrivilegedExecutables`). Distributed builds need
`anchor apple generic` in both requirements, with the app and helper signed by the same
Developer ID identity (`CERBERUS_CODESIGN_IDENTITY`), and the app notarized.

`SMJobBless` has been deprecated since macOS 13 in favor of `SMAppService`. It is still
present and works, and it remains the development path here. `SMAppService` requires apps
that contain LaunchDaemons to be notarized, so moving to it is tied to Developer ID
signing and notarization; Apple also requires an administrator to approve the daemon in
System Settings. The packaging scripts keep the helper plist and IPC transport ready for
that migration.

---

## Deployment Modes

### Desktop (recommended)

The Wails app starts the daemon in-process. The UI receives data through IPC and
subscribes to log and scan events.

### Headless daemon

`cmd/sentinel` runs the same daemon without a UI. It serves only the loopback agent
ingest listener and logs to stderr (also kept in memory for diagnostics).

```bash
export CERBERUS_SUBNET="192.168.1.0/24"
export CERBERUS_ENROLL_TOKEN="change-me"
./bin/sentinel
```

### Agent ingestion

Agent telemetry is accepted only on loopback in this release:

```bash
export CERBERUS_INGEST_PORT=8080          # default
export CERBERUS_INGEST_HOST=127.0.0.1     # non-loopback values are refused
export CERBERUS_ENROLL_TOKEN="change-me"  # enrollment is disabled when empty
```

`POST /api/v1/agent/enroll` issues a bearer token; `POST /api/v1/agent/telemetry`
accepts batches. Remote/LAN ingestion and the UI that consumes agent telemetry are
tracked as future work (issues #8 follow-up and #12).

---

## Configuration Reference

Environment variables:

| Variable | Description | Default |
|---|---|---|
| `CERBERUS_INGEST_PORT` | Loopback agent ingest port | `8080` |
| `CERBERUS_INGEST_HOST` | Ingest bind address; forced to loopback if not loopback | `127.0.0.1` |
| `CERBERUS_DISABLE_INGEST` | Disable the agent ingest listener entirely | `false` |
| `CERBERUS_DB_PATH` | SQLite database path | `cerberus.db` (OS data dir in the desktop app) |
| `CERBERUS_SUBNET` | Target CIDR; omitted means auto-detect | auto-detect |
| `CERBERUS_DISCOVERY_INTERVAL` | Known-device check interval after the startup full sweep | `5m` |
| `CERBERUS_VULN_INTERVAL` | Vulnerability audit interval | `20m` |
| `CERBERUS_ENROLL_TOKEN` | Shared enrollment secret for agents | *empty (disabled)* |
| `CERBERUS_SCAN_PORTS` | Port scope: empty (full `1-65535`), `1-10000`, `22,80,443`, or `--top-ports N` | *empty* |
| `CERBERUS_NMAP_PATH` | Explicit nmap path | `nmap` / bundled |
| `CERBERUS_VULN_SCRIPT` | nmap NSE script used in Stage 3 | `vulners` |
| `CERBERUS_SCAN_TIMEOUT` | Maximum duration of one scan job | `15m` |
| `CERBERUS_IMMEDIATE_DELAY` | Grace period before auditing a newly discovered host | `3s` |
| `CERBERUS_INGEST_MAX_BODY` | Maximum raw ingest request size | `1048576` |
| `CERBERUS_INGEST_SHARDS` | Dispatcher shard count | `GOMAXPROCS` |
| `CERBERUS_EVENT_RETENTION` | Agent event retention | `168h` |

Saved settings from the desktop Settings page override the interval defaults on the
next launch. Changing settings applies immediately without a restart and starts a
discovery sweep of the new target.

---

## Building from Source

### Headless daemon

```bash
make build-headless
```

### Desktop app (Wails v2)

Requires the Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0`)
and the platform toolchain.

macOS — initialize the `front` submodule, then build the universal app and DMG:

```bash
git submodule update --init --recursive
./build-macos.sh
```

Linux — requires `libgtk-3-dev` and `libwebkit2gtk-4.1-dev`:

```bash
make build-desktop
```

macOS privileged helper — `build-dmg.sh` builds and injects the helper automatically.
For a local development build, run:

```bash
cd desktop && wails build
cd ..
./scripts/install_helper_dev.sh
```

The script builds `com.cerberus.helper` with the embedded plists, places it in
`Contents/Library/LaunchServices/`, signs the app and helper, and launches the app so
SMJobBless can raise the Touch ID / administrator prompt. Set
`CERBERUS_CODESIGN_IDENTITY` to a Developer ID identity for a release-like signature.

A Developer ID is **not required for local testing**. The development plists use
identifier-only requirements, and the app's `CFBundleIdentifier`
(`io.github.gr0gu.cerberus`) must match the helper's `SMAuthorizedClients`; the helper's
`CFBundleIdentifier` (`com.cerberus.helper`) must match the app's
`SMPrivilegedExecutables`. The default ad-hoc signature satisfies both. If SMJobBless
still refuses an ad-hoc pair, install the helper directly for development:

```bash
./scripts/install_helper_root_dev.sh
```

That bypasses the native install prompt and is for development only. A production build
must tighten both requirements with `and anchor apple generic`, sign the app and helper
with the same Developer ID, and notarize the app.

Windows — install Npcap on the target machine, then build with the Wails CLI. Release
CI downloads portable nmap and RustScan into `desktop/tools/`; the resulting
executable requests administrator privileges at launch.

### Agent

The agent lives in the sibling `cerberus-agent` repository and requires Linux kernel
5.8+ with BTF, `clang`, `llvm`, and `libbpf-dev`:

```bash
git clone https://github.com/gr0gu/cerberus-agent.git
cd cerberus-agent
sudo ./setup.sh
make clean && make
```

### Tests

```bash
go test -race -count=1 ./...
```

Automated coverage for the new scan, scheduler, and ingest paths is tracked in
issue #13.

---

## Project Layout

```
cmd/sentinel          Headless daemon entrypoint
cmd/helper            macOS privileged helper
desktop               Wails app and IPC bridge
front                 React frontend (git submodule)
internal/app          Daemon lifecycle and IPC business methods
internal/scanner      Tri-stage HybridEngine, nmap/RustScan runners, preflight
internal/scheduler    Periodic workers, serialized scan gate, persistence
internal/ingest       Loopback agent ingest server and telemetry pipeline
internal/detect       Detection rules and incident engine
internal/identity     3-tier identity matcher
internal/posture      Fleet posture scoring
internal/storage      SQLite schema, migrations, queries
docs/ipc-api.md       Desktop IPC contract
openapi.yaml          Loopback agent ingest API
```

---

## Known Deferred Work

These are tracked as GitHub issues and are intentionally not part of this release:

- **#11** — harden the local security model (helper peer validation, ingest rate
  limiting and token rotation, opt-in tracking, file permissions, signing).
- **#12** — consume agent telemetry in the UI and detection pipeline.
- **#13** — increase automated test coverage for scanning, scheduling, and ingest.

See the repository issue tracker for the full list.
