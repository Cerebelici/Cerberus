# Cerberus Desktop IPC API

The desktop UI talks to the Go daemon through **Wails v2 IPC**. There is no UI HTTP
API: the only HTTP listener is the loopback agent ingest endpoint described in
[`openapi.yaml`](../openapi.yaml).

The bridge is implemented in [`desktop/bridge.go`](../desktop/bridge.go) and exposed
to the frontend as `window.go.main.Bridge`. The TypeScript contract and path-to-method
router live in [`front/src/api/wailsBridge.ts`](../front/src/api/wailsBridge.ts).

All methods return a Promise. A rejected Promise is the IPC equivalent of a failed
request; error messages are user-presentable. There are no HTTP status codes. Manual
scan conflict is reported in-band with `status: "conflict"` and is converted to an
error by the frontend bridge adapter.

## Transport notes

- Every call uses the Wails runtime context captured at startup.
- Objects use the JSON tags defined in `internal/model`.
- Reading state is cheap and idempotent; methods that change settings or delete data
  persist immediately to SQLite.
- The frontend still carries logical `/api/...` paths in `front/src/api/endpoints.ts`;
  `dispatchWailsIpc` maps them to bridge methods. They are not served over HTTP.

## Methods

### Status and posture

| Method | Parameters | Returns |
|---|---|---|
| `GetStatus()` | — | `SystemStatus` |
| `GetPosture()` | — | `PostureReport` |

`SystemStatus` contains uptime, device/service/vulnerability counters, next scheduled
runs, `is_discovery_running`, `is_vuln_running`, capabilities, ingest counters,
detection lag, open incidents, fleet score, and posture status.

### Timeline

| Method | Parameters | Returns |
|---|---|---|
| `GetTimeline(from, to, status, vulnerableOnly)` | RFC3339 timestamps (or an empty string), device status filter, vulnerability filter | `TimelineResponse` |

`from` also accepts a Go duration such as `24h`, interpreted relative to `to`.

### Devices

| Method | Parameters | Returns |
|---|---|---|
| `GetDevices(status)` | `""`, `"up"`, or `"down"` | `{ count, devices: Device[] }` |
| `GetDeviceByID(id)` | device id | `Device` |
| `UpdateDevice(id, label, criticality, notes)` | nullable string fields | Updated `Device` |
| `DeleteDevice(id)` | device id | `{ status: "deleted" }` |
| `ClearAllDevices()` | — | `{ status: "cleared", deleted }` |

Device results include risk and posture score, open services, vulnerabilities, and
identity metadata when available.

### Services and vulnerabilities

| Method | Parameters | Returns |
|---|---|---|
| `GetServices()` | — | `{ count, services: Service[] }` |
| `DeleteService(id)` | service id | `{ status: "deleted" }` |
| `GetVulnerabilities(severity)` | `""`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` | `{ count, vulnerabilities: Vulnerability[] }` |
| `DeleteVulnerability(id)` | vulnerability id | `{ status: "deleted" }` |

### Scans

| Method | Parameters | Returns |
|---|---|---|
| `GetScans(limit)` | maximum rows | `{ count, scans: ScanLog[] }` |
| `ClearScanHistory()` | — | `{ status: "cleared", deleted }` |
| `TriggerDiscovery()` | — | `ScanRequestResult` |
| `TriggerVulnerabilityScan()` | — | `ScanRequestResult` |
| `CancelScan()` | — | `{ status: "cancelled" | "idle" }` |

`ScanRequestResult` has these fields:

```json
{
  "status": "running | conflict | forbidden | unavailable",
  "message": "Discovery scan initiated in background",
  "error": "A discovery scan is already in progress",
  "scan_type": "discovery | vulnerability"
}
```

`message` is present for `running`; `error` is present for the other statuses. If
privileges are missing, the daemon asks the OS for elevation before queueing the scan.
When the user refuses, the request returns `forbidden` and no scan is queued. There is no
unprivileged connect-scan fallback.

Discovery and vulnerability pipelines are serialized by the scheduler: only one scan
runs at a time, and an immediate scan of a newly discovered host waits for the gate
instead of competing for nmap/RustScan and raw sockets.

### Logs and settings

| Method | Parameters | Returns |
|---|---|---|
| `GetLogs()` | — | `{ count, logs: LogEntry[] }` |
| `GetSettings()` | — | `SettingsResponse` |
| `UpdateSettings(settings)` | full `AppSettings` object | `SettingsResponse` |
| `SetupNmapAndPrivileges()` | — | `Capabilities` |

`SettingsResponse` is `{ settings, interfaces, capabilities }`. `UpdateSettings`
applies the new target, port scope, and intervals immediately and triggers a
discovery sweep of the new range. The following fields are accepted:

```json
{
  "network_mode": "auto | interface | custom",
  "selected_interface": "",
  "custom_network_cidr": "",
  "effective_cidr": "",
  "effective_exclude_ip": "",
  "scan_ports": "",
  "discovery_interval_sec": 300,
  "vuln_interval_sec": 1200,
  "nmap_path": ""
}
```

An empty `scan_ports` means the full 1-65535 TCP range. A range (`1-10000`), a list
(`22,80,443`), or `--top-ports N` is passed through the scan engine when explicitly
configured. The discovery interval controls the known-device check after the startup full
sweep; a full sweep also runs when the target changes or a manual discovery is requested.

## Events

The bridge also emits Wails runtime events. Subscribe with
`window.runtime.EventsOn(name, handler)`.

| Event | Payload |
|---|---|
| `cerberus:log` | `LogEntry` `{ seq, timestamp, level, source, message }` |
| `scan:stage_changed` | `"Stage 1: L2 Mapping"`, `"Stage 2: Port Sweep"`, `"Stage 3: Deep Audit"`, or `"Completed"` |
| `scan:host_discovered` | `{ ip, mac }` |
| `scan:identity_updated` | `{ ip, hostname, vendor }` |
| `scan:completed` | `{ type, devices }` for discovery or `{ type, results, duration_ms }` for audits |
| `daemon:error` | error string |

## Not exposed over IPC

Incident triage, posture history, and raw export were previously REST endpoints. They
are intentionally absent from this release's UI contract; incident data produced by the
detection engine is exposed only through `GetStatus` counters until the agent telemetry
UI work (issue #12) is implemented.
