package model

import "time"

// Device represents a network host discovered by Cerberus.
type Device struct {
	ID                   int64           `json:"id"`
	CurrentIP            string          `json:"current_ip"`
	IP                   string          `json:"ip"` // Backward-compatible alias for CurrentIP
	MAC                  string          `json:"mac,omitempty"`
	Hostname             string          `json:"hostname,omitempty"`
	Vendor               string          `json:"vendor,omitempty"`
	Status               string          `json:"status"` // "up" or "down"
	FirstSeen            time.Time       `json:"first_seen"`
	LastSeen             time.Time       `json:"last_seen"`
	AssetUID             string          `json:"asset_uid"`
	MACIsRandom          bool            `json:"mac_is_random"`
	PortProfileHash      string          `json:"port_profile_hash,omitempty"`
	Fingerprints         []string        `json:"fingerprints,omitempty"`
	Managed              bool            `json:"managed"`
	IdentityConfidence   float64         `json:"identity_confidence"`
	Label                string          `json:"label,omitempty"`
	Criticality          string          `json:"criticality"` // "low", "normal", "high", "critical"
	Notes                string          `json:"notes,omitempty"`
	Risk                 float64         `json:"risk,omitempty"`
	Score                float64         `json:"score,omitempty"`
	ServicesCount        int             `json:"services_count"`
	VulnerabilitiesCount int             `json:"vulnerabilities_count"`
	Services             []Service       `json:"services,omitempty"`
	Vulnerabilities      []Vulnerability `json:"vulnerabilities,omitempty"`
}

// DeviceAddress records an IP lease / network attachment history for a device.
type DeviceAddress struct {
	ID        int64     `json:"id"`
	DeviceID  int64     `json:"device_id"`
	IP        string    `json:"ip"`
	MAC       string    `json:"mac,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Closed    bool      `json:"closed"`
}

// IdentityDecision stores deterministic resolution audit logs.
type IdentityDecision struct {
	ID               int64     `json:"id"`
	ObservedAt       time.Time `json:"observed_at"`
	IP               string    `json:"ip"`
	MAC              string    `json:"mac,omitempty"`
	Hostname         string    `json:"hostname,omitempty"`
	ChosenDeviceID   *int64    `json:"chosen_device_id,omitempty"`
	Score            float64   `json:"score"`
	RunnerUpDeviceID *int64    `json:"runner_up_device_id,omitempty"`
	RunnerUpScore    float64   `json:"runner_up_score"`
	Reason           string    `json:"reason"`
}

// MergeDeviceRequest describes an administrative device merge (storage layer).
type MergeDeviceRequest struct {
	SourceID int64 `json:"source_id"`
}

// SplitDeviceRequest describes splitting an address lease into a device record (storage layer).
type SplitDeviceRequest struct {
	AddressID int64 `json:"address_id"`
}

// UpdateDeviceRequest carries editable device fields exposed through the IPC bridge.
type UpdateDeviceRequest struct {
	Label       *string `json:"label,omitempty"`
	Criticality *string `json:"criticality,omitempty"`
	Notes       *string `json:"notes,omitempty"`
}

// Service represents a network service running on an open port of a device.
type Service struct {
	ID              int64           `json:"id"`
	DeviceID        int64           `json:"device_id"`
	DeviceIP        string          `json:"device_ip,omitempty"`
	Port            int             `json:"port"`
	Protocol        string          `json:"protocol"` // "tcp" or "udp"
	ServiceName     string          `json:"service_name,omitempty"`
	Product         string          `json:"product,omitempty"`
	Version         string          `json:"version,omitempty"`
	State           string          `json:"state"` // "open", "filtered", "closed"
	UpdatedAt       time.Time       `json:"updated_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Vulnerability represents an identified CVE or security weakness.
type Vulnerability struct {
	ID              int64      `json:"id"`
	DeviceID        int64      `json:"device_id"`
	DeviceIP        string     `json:"device_ip,omitempty"`
	ServicePort     int        `json:"service_port"`
	CVEID           string     `json:"cve_id"`
	Title           string     `json:"title,omitempty"`
	Severity        string     `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"
	CVSSScore       float64    `json:"cvss_score"`
	Description     string     `json:"description,omitempty"`
	ReferenceURL    string     `json:"reference_url,omitempty"`
	DetectedAt      time.Time  `json:"detected_at"`
	IsExploit       bool       `json:"-"`
	ExploitRefs     []string   `json:"-"`
	Status          string     `json:"status"` // "open" | "resolved"
	FirstDetectedAt time.Time  `json:"first_detected_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
}

// ScanLog records historical scans executed by Cerberus.
type ScanLog struct {
	ID           int64      `json:"id"`
	ScanType     string     `json:"scan_type"` // "discovery", "vulnerability", "immediate"
	Status       string     `json:"status"`    // "running", "completed", "failed"
	TargetSpec   string     `json:"target_spec"`
	HostsFound   int        `json:"hosts_found"`
	VulnsFound   int        `json:"vulns_found"`
	DurationMs   int64      `json:"duration_ms"`
	ErrorMessage string     `json:"error_message,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// Capabilities describes the operational abilities and constraints of the scanner environment.
type Capabilities struct {
	NmapPath      string   `json:"nmap_path"`
	NmapVersion   string   `json:"nmap_version"`
	VulnScriptOK  bool     `json:"vuln_script_ok"`
	RawSocket     bool     `json:"raw_socket"`
	EffectiveMode string   `json:"effective_mode"` // "privileged" | "unprivileged"
	Warnings      []string `json:"warnings,omitempty"`
}

// SystemStatus provides a live snapshot of the sentinel.
type SystemStatus struct {
	Uptime               string        `json:"uptime"`
	UptimeSeconds        int64         `json:"uptime_seconds"`
	ActiveDevices        int           `json:"active_devices"`
	TotalDevices         int           `json:"total_devices"`
	TotalServices        int           `json:"total_services"`
	TotalVulnerabilities int           `json:"total_vulnerabilities"`
	DiscoveryNextRun     *time.Time    `json:"discovery_next_run,omitempty"`
	VulnNextRun          *time.Time    `json:"vuln_next_run,omitempty"`
	IsDiscoveryRunning   bool          `json:"is_discovery_running"`
	IsVulnRunning        bool          `json:"is_vuln_running"`
	Capabilities         *Capabilities `json:"capabilities"`
	IngestEventsTotal    int64         `json:"ingest_events_total"`
	DetectLagMsP95       float64       `json:"detect_lag_ms_p95"`
	IncidentsOpen        int           `json:"incidents_open"`
	FleetScore           *float64      `json:"fleet_score"`
	PostureStatus        string        `json:"posture_status,omitempty"`
}

// DevicePostureSummary contains the calculated risk and score for a single device.
type DevicePostureSummary struct {
	DeviceID  int64   `json:"device_id"`
	CurrentIP string  `json:"current_ip"`
	Hostname  string  `json:"hostname,omitempty"`
	Managed   bool    `json:"managed"`
	Risk      float64 `json:"risk"`
	Score     float64 `json:"score"`
	OpenVulns int     `json:"open_vulns"`
	MaxCVE    float64 `json:"max_cve"`
}

// PostureReport represents the calculated posture for the active fleet.
type PostureReport struct {
	ComputedAt    time.Time              `json:"computed_at"`
	PolicyVersion string                 `json:"policy_version"`
	FleetScore    *float64               `json:"fleet_score"`
	PostureStatus string                 `json:"posture_status,omitempty"`
	ActiveDevices int                    `json:"active_devices"`
	MeanRisk      float64                `json:"mean_risk"`
	MaxRisk       float64                `json:"max_risk"`
	PenaltyTotal  float64                `json:"penalty_total"`
	DeviceScores  []DevicePostureSummary `json:"device_scores"`
}

// PostureSnapshot represents a persisted posture snapshot in the database.
type PostureSnapshot struct {
	ID            int64          `json:"id"`
	ComputedAt    time.Time      `json:"computed_at"`
	PolicyVersion string         `json:"policy_version"`
	FleetScore    *float64       `json:"fleet_score"`
	ActiveDevices int            `json:"active_devices"`
	DetailsJSON   string         `json:"-"`
	Details       *PostureReport `json:"details,omitempty"`
}

// ExportData represents the complete network sentinel snapshot for JSON export.
type ExportData struct {
	ExportedAt           time.Time `json:"exported_at"`
	NetworkCIDR          string    `json:"network_cidr"`
	TotalDevices         int       `json:"total_devices"`
	TotalVulnerabilities int       `json:"total_vulnerabilities"`
	Devices              []Device  `json:"devices"`
}

// ScanHostResult holds parsed scan results for a single target host.
type ScanHostResult struct {
	IP              string
	MAC             string
	Vendor          string
	Hostname        string
	Status          string
	Fingerprints    []string
	Services        []Service
	Vulnerabilities []Vulnerability
}

// DeviceScanRecord stores a historical snapshot of a device during a specific scan.
type DeviceScanRecord struct {
	ID           int64     `json:"id"`
	DeviceID     int64     `json:"device_id"`
	ScanID       int64     `json:"scan_id"`
	Status       string    `json:"status"` // "up" or "down"
	IsVulnerable bool      `json:"is_vulnerable"`
	VulnsCount   int       `json:"vulns_count"`
	MaxSeverity  string    `json:"max_severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"
	RecordedAt   time.Time `json:"recorded_at"`
}

// ScanTick represents a point on the timeline scan line when an engine scan completed.
type ScanTick struct {
	ScanID     int64     `json:"scan_id"`
	Timestamp  time.Time `json:"timestamp"`
	ScanType   string    `json:"scan_type"`
	Status     string    `json:"status"`
	TargetSpec string    `json:"target_spec"`
	HostsFound int       `json:"hosts_found"`
	DurationMs int64     `json:"duration_ms"`
}

// TimelinePeriod represents a continuous activity interval for a device with uniform status and vulnerability metrics.
type TimelinePeriod struct {
	StartedAt              time.Time `json:"started_at"`
	EndedAt                time.Time `json:"ended_at"`
	Status                 string    `json:"status"`
	IsVulnerable           bool      `json:"is_vulnerable"`
	VulnsCount             int       `json:"vulns_count"`
	MaxSeverity            string    `json:"max_severity"`
	IsOngoing              bool      `json:"is_ongoing"`
	TransitionUncertaintyS int64     `json:"transition_uncertainty_s,omitempty"`
}

// TimelineDevice represents a device with its segmented activity periods for timeline visualization.
type TimelineDevice struct {
	DeviceID      int64            `json:"device_id"`
	IP            string           `json:"ip"`
	MAC           string           `json:"mac,omitempty"`
	Hostname      string           `json:"hostname,omitempty"`
	Vendor        string           `json:"vendor,omitempty"`
	CurrentStatus string           `json:"current_status"`
	Periods       []TimelinePeriod `json:"periods"`
}

// TimelineTimeWindow defines the bounds and high-level counts for a timeline query.
type TimelineTimeWindow struct {
	From         time.Time `json:"from"`
	To           time.Time `json:"to"`
	TotalScans   int       `json:"total_scans"`
	TotalDevices int       `json:"total_devices"`
}

// TimelineResponse is the complete payload returned by the GetTimeline IPC method.
type TimelineResponse struct {
	TimeWindow TimelineTimeWindow `json:"time_window"`
	ScanTicks  []ScanTick         `json:"scan_ticks"`
	Devices    []TimelineDevice   `json:"devices"`
}

// NetworkInterfaceInfo describes a local network interface and its IPv4 subnet.
type NetworkInterfaceInfo struct {
	Name      string `json:"name"`       // e.g. "en0", "eth0", "Wi-Fi"
	IPv4      string `json:"ipv4"`       // e.g. "192.168.1.42"
	CIDR      string `json:"cidr"`       // e.g. "192.168.1.0/24"
	MAC       string `json:"mac"`        // e.g. "aa:bb:cc:dd:ee:ff"
	IsDefault bool   `json:"is_default"` // True if primary outbound route
}

// AppSettings holds user-configurable and auto-detected runtime settings.
type AppSettings struct {
	NetworkMode          string `json:"network_mode"`           // "auto" | "interface" | "custom"
	SelectedInterface    string `json:"selected_interface"`     // e.g. "en0"
	CustomNetworkCIDR    string `json:"custom_network_cidr"`    // e.g. "192.168.1.0/24"
	EffectiveCIDR        string `json:"effective_cidr"`         // Target CIDR currently being scanned
	EffectiveExcludeIP   string `json:"effective_exclude_ip"`   // Host IP excluded from scan
	ScanPorts            string `json:"scan_ports"`             // "" (full 1-65535), a range, or custom "22,80,443"
	DiscoveryIntervalSec int    `json:"discovery_interval_sec"` // Interval between discovery scans in seconds
	VulnIntervalSec      int    `json:"vuln_interval_sec"`      // Interval between vuln scans in seconds
	NmapPath             string `json:"nmap_path"`              // Detected or user-overridden Nmap path
}

// SettingsResponse returns the persisted settings, available interfaces, and current scanner capabilities.
type SettingsResponse struct {
	Settings     AppSettings            `json:"settings"`
	Interfaces   []NetworkInterfaceInfo `json:"interfaces"`
	Capabilities *Capabilities          `json:"capabilities"`
}
