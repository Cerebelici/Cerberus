package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	_ "modernc.org/sqlite"
)

var memDBCounter int64

func formatDSN(path string, queryOnly bool) string {
	var base string
	if path == ":memory:" {
		id := atomic.AddInt64(&memDBCounter, 1)
		base = fmt.Sprintf("file:mem_%d?mode=memory&cache=shared&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_time_format=sqlite", id)
	} else if strings.HasPrefix(path, "file:") {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		base = fmt.Sprintf("%s%s_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_time_format=sqlite", path, sep)
	} else {
		base = fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_time_format=sqlite", path)
	}
	if queryOnly {
		base += "&_pragma=query_only(1)"
	}
	return base
}

// Storage handles all persistence logic with SQLite, with separated reader and writer pools.
type Storage struct {
	w                 *sql.DB
	r                 *sql.DB
	discoveryInterval atomic.Int64 // time.Duration; changed at runtime from settings
}

// Tx wraps an active write transaction.
type Tx struct {
	tx *sql.Tx
}

// Raw exposes the underlying *sql.Tx.
func (t *Tx) Raw() *sql.Tx {
	return t.tx
}

type execQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// New initializes the SQLite database, establishes tables, and configures WAL mode.
func New(dbPath string) (*Storage, error) {
	if dbPath != ":memory:" && !strings.Contains(dbPath, "mode=memory") {
		dir := filepath.Dir(dbPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
			}
		}
	}

	dsnW := formatDSN(dbPath, false)
	dsnR := dsnW + "&_pragma=query_only(1)"

	w, err := sql.Open("sqlite", dsnW)
	if err != nil {
		return nil, fmt.Errorf("failed to open writer database: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)

	r, err := sql.Open("sqlite", dsnR)
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("failed to open reader database: %w", err)
	}
	r.SetMaxOpenConns(4)
	r.SetMaxIdleConns(4)

	s := &Storage{
		w: w,
		r: r,
	}
	s.discoveryInterval.Store(int64(30 * time.Minute))

	if err := s.runMigrations(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

// SetDiscoveryInterval configures the discovery interval used for ongoing period calculations.
func (s *Storage) SetDiscoveryInterval(d time.Duration) {
	if d > 0 {
		s.discoveryInterval.Store(int64(d))
	}
}

// WithTx executes the given function in a transaction on the writer connection.
func (s *Storage) WithTx(ctx context.Context, fn func(tx *Tx) error) error {
	nativeTx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	t := &Tx{tx: nativeTx}
	if err := fn(t); err != nil {
		_ = nativeTx.Rollback()
		return err
	}
	if err := nativeTx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// Close closes the underlying writer and reader database handles.
func (s *Storage) Close() error {
	errW := s.w.Close()
	errR := s.r.Close()
	if errW != nil {
		return errW
	}
	return errR
}

// RawReader exposes the read connection pool (useful for tests).
func (s *Storage) RawReader() *sql.DB {
	return s.r
}

// RawWriter exposes the write connection pool (useful for tests).
func (s *Storage) RawWriter() *sql.DB {
	return s.w
}

// UpsertService saves or updates a detected service for a device.
func (s *Storage) UpsertService(ctx context.Context, svc *model.Service) (*model.Service, error) {
	return upsertServiceInternal(ctx, s.w, svc)
}

func (t *Tx) UpsertService(ctx context.Context, svc *model.Service) (*model.Service, error) {
	return upsertServiceInternal(ctx, t.tx, svc)
}

func upsertServiceInternal(ctx context.Context, eq execQuerier, svc *model.Service) (*model.Service, error) {
	now := time.Now().UTC()
	query := `INSERT INTO services (device_id, port, protocol, service_name, product, version, state, updated_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id, port, protocol) DO UPDATE SET
			service_name = excluded.service_name,
			product = excluded.product,
			version = excluded.version,
			state = excluded.state,
			updated_at = excluded.updated_at,
			last_seen_at = excluded.last_seen_at
		RETURNING id;`

	state := svc.State
	if state == "" {
		state = "open"
	}

	var id int64
	err := eq.QueryRowContext(ctx, query,
		svc.DeviceID, svc.Port, svc.Protocol, svc.ServiceName, svc.Product, svc.Version, state, now, now,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("upserting service: %w", err)
	}

	svc.ID = id
	svc.UpdatedAt = now
	return svc, nil
}

// UpsertVulnerability saves a detected vulnerability or updates its details.
func (s *Storage) UpsertVulnerability(ctx context.Context, v *model.Vulnerability) (*model.Vulnerability, bool, error) {
	return upsertVulnerabilityInternal(ctx, s.w, v)
}

func (t *Tx) UpsertVulnerability(ctx context.Context, v *model.Vulnerability) (*model.Vulnerability, bool, error) {
	return upsertVulnerabilityInternal(ctx, t.tx, v)
}

func upsertVulnerabilityInternal(ctx context.Context, eq execQuerier, v *model.Vulnerability) (*model.Vulnerability, bool, error) {
	now := time.Now().UTC()
	firstDetected := v.FirstDetectedAt.UTC()
	if firstDetected.IsZero() {
		firstDetected = now
	}
	v.LastSeenAt = now
	v.Status = "open"
	v.ResolvedAt = nil
	v.DetectedAt = now

	exploitRefsJSON, err := json.Marshal(v.ExploitRefs)
	if err != nil {
		exploitRefsJSON = []byte("[]")
	}
	isExploitInt := 0
	if v.IsExploit {
		isExploitInt = 1
	}
	severity := strings.ToUpper(v.Severity)
	if severity == "" {
		severity = "UNKNOWN"
	}
	v.Severity = severity

	var existingID int64
	var existingFirstDetected sql.NullTime
	checkQuery := `SELECT id, first_detected_at FROM vulnerabilities WHERE device_id = ? AND service_port = ? AND cve_id = ?;`
	err = eq.QueryRowContext(ctx, checkQuery, v.DeviceID, v.ServicePort, v.CVEID).Scan(&existingID, &existingFirstDetected)

	if err == sql.ErrNoRows {
		insertQuery := `INSERT INTO vulnerabilities (
			device_id, service_port, cve_id, title, severity, cvss_score, description, reference_url,
			detected_at, is_exploit, exploit_refs, status, first_detected_at, last_seen_at, resolved_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);`
		res, err := eq.ExecContext(ctx, insertQuery,
			v.DeviceID, v.ServicePort, v.CVEID, v.Title, severity, v.CVSSScore, v.Description, v.ReferenceURL,
			now, isExploitInt, string(exploitRefsJSON), "open", firstDetected, now,
		)
		if err != nil {
			return nil, false, fmt.Errorf("inserting vulnerability: %w", err)
		}
		id, _ := res.LastInsertId()
		v.ID = id
		v.FirstDetectedAt = firstDetected
		return v, true, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("checking vulnerability: %w", err)
	}

	updateQuery := `UPDATE vulnerabilities SET
		title = COALESCE(NULLIF(?, ''), title),
		severity = COALESCE(NULLIF(?, ''), severity),
		cvss_score = CASE WHEN ? > 0 THEN ? ELSE cvss_score END,
		description = COALESCE(NULLIF(?, ''), description),
		reference_url = COALESCE(NULLIF(?, ''), reference_url),
		detected_at = ?,
		is_exploit = ?,
		exploit_refs = ?,
		status = 'open',
		last_seen_at = ?,
		resolved_at = NULL
		WHERE id = ?;`

	_, err = eq.ExecContext(ctx, updateQuery,
		v.Title, severity, v.CVSSScore, v.CVSSScore, v.Description, v.ReferenceURL,
		now, isExploitInt, string(exploitRefsJSON), now, existingID,
	)
	if err != nil {
		return nil, false, fmt.Errorf("updating vulnerability: %w", err)
	}

	v.ID = existingID
	if existingFirstDetected.Valid {
		v.FirstDetectedAt = existingFirstDetected.Time
	}
	return v, false, nil
}

// ReconcileHostFindings marks unobserved vulnerabilities as resolved and unobserved services as closed for an active host.
func (s *Storage) ReconcileHostFindings(ctx context.Context, deviceID int64, scanStart time.Time, observedPorts []int) error {
	return reconcileHostFindingsInternal(ctx, s.w, deviceID, scanStart, observedPorts)
}

func (t *Tx) ReconcileHostFindings(ctx context.Context, deviceID int64, scanStart time.Time, observedPorts []int) error {
	return reconcileHostFindingsInternal(ctx, t.tx, deviceID, scanStart, observedPorts)
}

func reconcileHostFindingsInternal(ctx context.Context, eq execQuerier, deviceID int64, scanStart time.Time, observedPorts []int) error {
	scanStartUTC := scanStart.UTC()

	// 1. Resolve open vulnerabilities not seen in this scan
	vulnQuery := `UPDATE vulnerabilities SET status = 'resolved', resolved_at = ?
		WHERE device_id = ? AND status = 'open' AND (last_seen_at < ? OR last_seen_at IS NULL);`
	if _, err := eq.ExecContext(ctx, vulnQuery, scanStartUTC, deviceID, scanStartUTC); err != nil {
		return fmt.Errorf("reconciling vulnerabilities for device %d: %w", deviceID, err)
	}

	// 2. Mark services not observed in this scan as closed
	if len(observedPorts) == 0 {
		svcQuery := `UPDATE services SET state = 'closed', updated_at = ? WHERE device_id = ? AND state != 'closed';`
		if _, err := eq.ExecContext(ctx, svcQuery, scanStartUTC, deviceID); err != nil {
			return fmt.Errorf("closing unobserved services for device %d: %w", deviceID, err)
		}
	} else {
		placeholders := make([]string, len(observedPorts))
		args := make([]any, 0, 2+len(observedPorts))
		args = append(args, scanStartUTC, deviceID)
		for i, p := range observedPorts {
			placeholders[i] = "?"
			args = append(args, p)
		}
		svcQuery := fmt.Sprintf(`UPDATE services SET state = 'closed', updated_at = ? WHERE device_id = ? AND port NOT IN (%s) AND state != 'closed';`, strings.Join(placeholders, ","))
		if _, err := eq.ExecContext(ctx, svcQuery, args...); err != nil {
			return fmt.Errorf("closing unobserved services for device %d: %w", deviceID, err)
		}
	}

	return nil
}

func (s *Storage) getServicesForDevice(ctx context.Context, deviceID int64, deviceIP string) ([]model.Service, error) {
	query := `SELECT id, device_id, port, protocol, COALESCE(service_name, ''), COALESCE(product, ''), COALESCE(version, ''), state, updated_at
		FROM services WHERE device_id = ? ORDER BY port ASC;`

	rows, err := s.r.QueryContext(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("querying services for device %d: %w", deviceID, err)
	}
	defer rows.Close()

	var services []model.Service
	for rows.Next() {
		var svc model.Service
		if err := rows.Scan(&svc.ID, &svc.DeviceID, &svc.Port, &svc.Protocol, &svc.ServiceName, &svc.Product, &svc.Version, &svc.State, &svc.UpdatedAt); err != nil {
			return nil, err
		}
		svc.DeviceIP = deviceIP
		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating services for device %d: %w", deviceID, err)
	}
	return services, nil
}

func (s *Storage) getVulnerabilitiesForDevice(ctx context.Context, deviceID int64, deviceIP string) ([]model.Vulnerability, error) {
	query := `SELECT id, device_id, service_port, cve_id, COALESCE(title, ''), severity, cvss_score, COALESCE(description, ''), COALESCE(reference_url, ''), detected_at,
		is_exploit, COALESCE(exploit_refs, '[]'), status, first_detected_at, last_seen_at, resolved_at
		FROM vulnerabilities WHERE device_id = ? AND status = 'open' ORDER BY cvss_score DESC;`

	rows, err := s.r.QueryContext(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerabilities for device %d: %w", deviceID, err)
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		var isExploit int
		var exploitRefsJSON sql.NullString
		var firstDetectedAt, lastSeenAt, resolvedAt sql.NullTime

		if err := rows.Scan(
			&v.ID, &v.DeviceID, &v.ServicePort, &v.CVEID, &v.Title,
			&v.Severity, &v.CVSSScore, &v.Description, &v.ReferenceURL, &v.DetectedAt,
			&isExploit, &exploitRefsJSON, &v.Status, &firstDetectedAt, &lastSeenAt, &resolvedAt,
		); err != nil {
			return nil, err
		}
		v.DeviceIP = deviceIP
		v.IsExploit = isExploit != 0
		if exploitRefsJSON.Valid && exploitRefsJSON.String != "" {
			_ = json.Unmarshal([]byte(exploitRefsJSON.String), &v.ExploitRefs)
		}
		if firstDetectedAt.Valid {
			v.FirstDetectedAt = firstDetectedAt.Time
		} else {
			v.FirstDetectedAt = v.DetectedAt
		}
		if lastSeenAt.Valid {
			v.LastSeenAt = lastSeenAt.Time
		} else {
			v.LastSeenAt = v.DetectedAt
		}
		if resolvedAt.Valid {
			v.ResolvedAt = &resolvedAt.Time
		}
		vulns = append(vulns, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerabilities: %w", err)
	}
	return vulns, nil
}

// GetAllServices retrieves all detected services across all devices.
func (s *Storage) GetAllServices(ctx context.Context) ([]model.Service, error) {
	query := `SELECT s.id, s.device_id, d.current_ip, s.port, s.protocol, COALESCE(s.service_name, ''),
		COALESCE(s.product, ''), COALESCE(s.version, ''), s.state, s.updated_at
		FROM services s
		JOIN devices d ON d.id = s.device_id
		ORDER BY d.current_ip ASC, s.port ASC;`

	rows, err := s.r.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("querying all services: %w", err)
	}
	defer rows.Close()

	var services []model.Service
	for rows.Next() {
		var svc model.Service
		if err := rows.Scan(&svc.ID, &svc.DeviceID, &svc.DeviceIP, &svc.Port, &svc.Protocol, &svc.ServiceName, &svc.Product, &svc.Version, &svc.State, &svc.UpdatedAt); err != nil {
			return nil, err
		}
		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating all services: %w", err)
	}
	return services, nil
}

// GetAllVulnerabilities retrieves all detected CVEs, optionally filtered by severity.
func (s *Storage) GetAllVulnerabilities(ctx context.Context, severity string) ([]model.Vulnerability, error) {
	query := `SELECT v.id, v.device_id, d.current_ip, v.service_port, v.cve_id, COALESCE(v.title, ''),
		v.severity, v.cvss_score, COALESCE(v.description, ''), COALESCE(v.reference_url, ''), v.detected_at,
		v.is_exploit, COALESCE(v.exploit_refs, '[]'), v.status, v.first_detected_at, v.last_seen_at, v.resolved_at
		FROM vulnerabilities v
		JOIN devices d ON d.id = v.device_id`

	var rows *sql.Rows
	var err error

	if severity != "" {
		query += ` WHERE v.severity = ? ORDER BY v.cvss_score DESC, v.detected_at DESC;`
		rows, err = s.r.QueryContext(ctx, query, strings.ToUpper(severity))
	} else {
		query += ` ORDER BY v.cvss_score DESC, v.detected_at DESC;`
		rows, err = s.r.QueryContext(ctx, query)
	}

	if err != nil {
		return nil, fmt.Errorf("querying vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		var isExploit int
		var exploitRefsJSON sql.NullString
		var firstDetectedAt, lastSeenAt, resolvedAt sql.NullTime

		if err := rows.Scan(
			&v.ID, &v.DeviceID, &v.DeviceIP, &v.ServicePort, &v.CVEID, &v.Title,
			&v.Severity, &v.CVSSScore, &v.Description, &v.ReferenceURL, &v.DetectedAt,
			&isExploit, &exploitRefsJSON, &v.Status, &firstDetectedAt, &lastSeenAt, &resolvedAt,
		); err != nil {
			return nil, err
		}
		v.IsExploit = isExploit != 0
		if exploitRefsJSON.Valid && exploitRefsJSON.String != "" {
			_ = json.Unmarshal([]byte(exploitRefsJSON.String), &v.ExploitRefs)
		}
		if firstDetectedAt.Valid {
			v.FirstDetectedAt = firstDetectedAt.Time
		} else {
			v.FirstDetectedAt = v.DetectedAt
		}
		if lastSeenAt.Valid {
			v.LastSeenAt = lastSeenAt.Time
		} else {
			v.LastSeenAt = v.DetectedAt
		}
		if resolvedAt.Valid {
			v.ResolvedAt = &resolvedAt.Time
		}
		vulns = append(vulns, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating vulnerabilities: %w", err)
	}
	return vulns, nil
}

// CreateScanLog creates a new scan log entry.
func (s *Storage) CreateScanLog(ctx context.Context, log *model.ScanLog) (*model.ScanLog, error) {
	startedAt := log.StartedAt.UTC()
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	query := `INSERT INTO scans (scan_type, status, target_spec, hosts_found, vulns_found, duration_ms, error_message, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

	res, err := s.w.ExecContext(ctx, query,
		log.ScanType, log.Status, log.TargetSpec, log.HostsFound, log.VulnsFound, log.DurationMs, log.ErrorMessage, startedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting scan log: %w", err)
	}

	id, _ := res.LastInsertId()
	log.ID = id
	log.StartedAt = startedAt
	return log, nil
}

// UpdateScanLog updates an existing scan log upon completion or failure.
func (s *Storage) UpdateScanLog(ctx context.Context, log *model.ScanLog) error {
	now := time.Now().UTC()
	query := `UPDATE scans SET
		status = ?,
		hosts_found = ?,
		vulns_found = ?,
		duration_ms = ?,
		error_message = ?,
		completed_at = ?
		WHERE id = ?;`

	_, err := s.w.ExecContext(ctx, query,
		log.Status, log.HostsFound, log.VulnsFound, log.DurationMs, log.ErrorMessage, now, log.ID,
	)
	if err != nil {
		return fmt.Errorf("updating scan log %d: %w", log.ID, err)
	}
	log.CompletedAt = &now
	return nil
}

// FailInterruptedScans marks scans still recorded as running as failed. Call it at startup:
// a scan from an earlier process that ended without updating its record (crash, forced
// quit) would otherwise stay "running" forever.
func (s *Storage) FailInterruptedScans(ctx context.Context, message string) (int64, error) {
	res, err := s.w.ExecContext(ctx,
		`UPDATE scans SET status = 'failed', error_message = ?, completed_at = ? WHERE status = 'running';`,
		message, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("failing interrupted scans: %w", err)
	}
	return res.RowsAffected()
}

// GetRecentScans returns the most recent scan logs.
func (s *Storage) GetRecentScans(ctx context.Context, limit int) ([]model.ScanLog, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, scan_type, status, target_spec, hosts_found, vulns_found, duration_ms,
		COALESCE(error_message, ''), started_at, completed_at
		FROM scans ORDER BY started_at DESC LIMIT ?;`

	rows, err := s.r.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("querying scans: %w", err)
	}
	defer rows.Close()

	var logs []model.ScanLog
	for rows.Next() {
		var l model.ScanLog
		if err := rows.Scan(&l.ID, &l.ScanType, &l.Status, &l.TargetSpec, &l.HostsFound, &l.VulnsFound, &l.DurationMs, &l.ErrorMessage, &l.StartedAt, &l.CompletedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating scans: %w", err)
	}
	return logs, nil
}

// GetCounts returns summary statistics for dashboard status.
func (s *Storage) GetCounts(ctx context.Context) (totalDevs, activeDevs, totalSvcs, totalVulns int, err error) {
	_ = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices;`).Scan(&totalDevs)
	_ = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE status = 'up';`).Scan(&activeDevs)
	_ = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM services WHERE state = 'open';`).Scan(&totalSvcs)
	_ = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open';`).Scan(&totalVulns)

	return totalDevs, activeDevs, totalSvcs, totalVulns, nil
}

// ExportAllData produces a full JSON-ready snapshot of devices, services, and vulnerabilities.
func (s *Storage) ExportAllData(ctx context.Context, cidr string) (*model.ExportData, error) {
	devices, err := s.GetDevices(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("exporting devices: %w", err)
	}

	totalVulns := 0
	for i := range devices {
		services, err := s.getServicesForDevice(ctx, devices[i].ID, devices[i].IP)
		if err != nil {
			return nil, err
		}
		devices[i].Services = services
		devices[i].ServicesCount = len(services)

		vulns, err := s.getVulnerabilitiesForDevice(ctx, devices[i].ID, devices[i].IP)
		if err != nil {
			return nil, err
		}
		devices[i].Vulnerabilities = vulns
		devices[i].VulnerabilitiesCount = len(vulns)
		totalVulns += len(vulns)
	}

	return &model.ExportData{
		ExportedAt:           time.Now().UTC(),
		NetworkCIDR:          cidr,
		TotalDevices:         len(devices),
		TotalVulnerabilities: totalVulns,
		Devices:              devices,
	}, nil
}

// RecordDeviceScanObservation writes a point-in-time device observation snapshot.
func (s *Storage) RecordDeviceScanObservation(ctx context.Context, record *model.DeviceScanRecord) error {
	return recordDeviceScanObservationInternal(ctx, s.w, record)
}

func (t *Tx) RecordDeviceScanObservation(ctx context.Context, record *model.DeviceScanRecord) error {
	return recordDeviceScanObservationInternal(ctx, t.tx, record)
}

func recordDeviceScanObservationInternal(ctx context.Context, eq execQuerier, record *model.DeviceScanRecord) error {
	if record.RecordedAt.IsZero() {
		record.RecordedAt = time.Now().UTC()
	} else {
		record.RecordedAt = record.RecordedAt.UTC()
	}
	if record.Status == "" {
		record.Status = "up"
	}
	if record.MaxSeverity == "" {
		record.MaxSeverity = "NONE"
	}

	isVulnInt := 0
	if record.IsVulnerable {
		isVulnInt = 1
	}

	query := `INSERT INTO device_scan_records (device_id, scan_id, status, is_vulnerable, vulns_count, max_severity, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?);`
	res, err := eq.ExecContext(ctx, query,
		record.DeviceID, record.ScanID, record.Status, isVulnInt, record.VulnsCount, record.MaxSeverity, record.RecordedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting device scan record: %w", err)
	}
	id, _ := res.LastInsertId()
	record.ID = id
	return nil
}

// GetDeviceSecurityPosture evaluates the current vulnerability count and max severity for a device.
func (s *Storage) GetDeviceSecurityPosture(ctx context.Context, deviceID int64) (bool, int, string, error) {
	return getDeviceSecurityPostureInternal(ctx, s.r, deviceID)
}

func (t *Tx) GetDeviceSecurityPosture(ctx context.Context, deviceID int64) (bool, int, string, error) {
	return getDeviceSecurityPostureInternal(ctx, t.tx, deviceID)
}

func getDeviceSecurityPostureInternal(ctx context.Context, eq execQuerier, deviceID int64) (bool, int, string, error) {
	query := `SELECT COALESCE(severity, 'UNKNOWN') FROM vulnerabilities WHERE device_id = ? AND status = 'open';`
	rows, err := eq.QueryContext(ctx, query, deviceID)
	if err != nil {
		return false, 0, "NONE", fmt.Errorf("querying vulnerabilities for posture: %w", err)
	}
	defer rows.Close()

	vulnsCount := 0
	highestRank := 0
	maxSeverity := "NONE"

	for rows.Next() {
		var sev string
		if err := rows.Scan(&sev); err != nil {
			return false, 0, "NONE", err
		}
		vulnsCount++
		rank := severityRank(sev)
		if rank > highestRank {
			highestRank = rank
			maxSeverity = sev
		}
	}

	return vulnsCount > 0, vulnsCount, maxSeverity, nil
}

func severityRank(sev string) int {
	switch sev {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "UNKNOWN":
		return 1
	default:
		return 0
	}
}

// PurgeOlderThan purges scan records and scans older than the specified retention age.
func (s *Storage) PurgeOlderThan(ctx context.Context, recordsAge, scansAge time.Duration) (int64, int64, error) {
	recordsCutoff := time.Now().UTC().Add(-recordsAge)
	scansCutoff := time.Now().UTC().Add(-scansAge)

	var deletedRecords, deletedScans int64

	err := s.WithTx(ctx, func(tx *Tx) error {
		resRec, err := tx.tx.ExecContext(ctx, "DELETE FROM device_scan_records WHERE recorded_at < ?;", recordsCutoff)
		if err != nil {
			return fmt.Errorf("purging old records: %w", err)
		}
		deletedRecords, _ = resRec.RowsAffected()

		resScans, err := tx.tx.ExecContext(ctx, "DELETE FROM scans WHERE started_at < ?;", scansCutoff)
		if err != nil {
			return fmt.Errorf("purging old scans: %w", err)
		}
		deletedScans, _ = resScans.RowsAffected()

		return nil
	})

	return deletedRecords, deletedScans, err
}

// GetTimeline returns scan ticks and continuous device activity periods across a time window.
func (s *Storage) GetTimeline(ctx context.Context, from, to time.Time, statusFilter string, vulnerableOnly bool) (*model.TimelineResponse, error) {
	now := time.Now().UTC()
	if to.IsZero() {
		to = now
	} else {
		to = to.UTC()
	}
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	} else {
		from = from.UTC()
	}

	// 1. Fetch scan ticks in time window
	scanQuery := `SELECT id, started_at, scan_type, status, target_spec, hosts_found, duration_ms
		FROM scans WHERE started_at >= ? AND started_at <= ? ORDER BY started_at ASC;`
	scanRows, err := s.r.QueryContext(ctx, scanQuery, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying scans for timeline: %w", err)
	}
	defer scanRows.Close()

	var scanTicks []model.ScanTick
	for scanRows.Next() {
		var tick model.ScanTick
		if err := scanRows.Scan(&tick.ScanID, &tick.Timestamp, &tick.ScanType, &tick.Status, &tick.TargetSpec, &tick.HostsFound, &tick.DurationMs); err != nil {
			return nil, fmt.Errorf("scanning scan tick: %w", err)
		}
		scanTicks = append(scanTicks, tick)
	}
	if err := scanRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating scan ticks: %w", err)
	}
	scanRows.Close()
	if scanTicks == nil {
		scanTicks = []model.ScanTick{}
	}

	// 2. Fetch devices (with optional status filter)
	devQuery := `SELECT id, current_ip AS ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''), status, first_seen, last_seen FROM devices`
	var devRows *sql.Rows
	if statusFilter != "" {
		devQuery += ` WHERE status = ? ORDER BY current_ip ASC;`
		devRows, err = s.r.QueryContext(ctx, devQuery, statusFilter)
	} else {
		devQuery += ` ORDER BY current_ip ASC;`
		devRows, err = s.r.QueryContext(ctx, devQuery)
	}
	if err != nil {
		return nil, fmt.Errorf("querying devices for timeline: %w", err)
	}
	defer devRows.Close()

	type devMeta struct {
		id        int64
		ip        string
		mac       string
		hostname  string
		vendor    string
		status    string
		firstSeen time.Time
		lastSeen  time.Time
	}
	var devList []devMeta
	for devRows.Next() {
		var d devMeta
		if err := devRows.Scan(&d.id, &d.ip, &d.mac, &d.hostname, &d.vendor, &d.status, &d.firstSeen, &d.lastSeen); err != nil {
			return nil, fmt.Errorf("scanning device: %w", err)
		}
		devList = append(devList, d)
	}
	if err := devRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating devices: %w", err)
	}
	devRows.Close()

	// 3. Carry-in records: last record before 'from' for each device
	carryInQuery := `SELECT r.device_id, r.status, r.is_vulnerable, r.vulns_count, r.max_severity, r.recorded_at
		FROM device_scan_records r
		JOIN (SELECT device_id, MAX(recorded_at) m FROM device_scan_records
		      WHERE recorded_at < ? GROUP BY device_id) p
		  ON p.device_id = r.device_id AND p.m = r.recorded_at;`
	carryRows, err := s.r.QueryContext(ctx, carryInQuery, from)
	if err != nil {
		return nil, fmt.Errorf("querying carry-in records: %w", err)
	}
	defer carryRows.Close()

	carryInByDev := make(map[int64]model.DeviceScanRecord)
	for carryRows.Next() {
		var rec model.DeviceScanRecord
		var isVulnInt int
		if err := carryRows.Scan(&rec.DeviceID, &rec.Status, &isVulnInt, &rec.VulnsCount, &rec.MaxSeverity, &rec.RecordedAt); err != nil {
			return nil, fmt.Errorf("scanning carry-in record: %w", err)
		}
		rec.IsVulnerable = isVulnInt == 1
		// Clamp recorded_at to 'from'
		rec.RecordedAt = from
		carryInByDev[rec.DeviceID] = rec
	}
	if err := carryRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating carry-in records: %w", err)
	}
	carryRows.Close()

	// 4. Fetch scan records for these devices inside time window
	recordQuery := `SELECT device_id, status, is_vulnerable, vulns_count, max_severity, recorded_at
		FROM device_scan_records
		WHERE recorded_at >= ? AND recorded_at <= ?
		ORDER BY device_id ASC, recorded_at ASC;`
	recRows, err := s.r.QueryContext(ctx, recordQuery, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying device scan records: %w", err)
	}
	defer recRows.Close()

	recordsByDev := make(map[int64][]model.DeviceScanRecord)
	for recRows.Next() {
		var rec model.DeviceScanRecord
		var isVulnInt int
		if err := recRows.Scan(&rec.DeviceID, &rec.Status, &isVulnInt, &rec.VulnsCount, &rec.MaxSeverity, &rec.RecordedAt); err != nil {
			return nil, fmt.Errorf("scanning record: %w", err)
		}
		rec.IsVulnerable = isVulnInt == 1
		recordsByDev[rec.DeviceID] = append(recordsByDev[rec.DeviceID], rec)
	}
	if err := recRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating device scan records: %w", err)
	}
	recRows.Close()

	// 5. Build timeline periods for each device
	var timelineDevices []model.TimelineDevice
	discoveryInterval := time.Duration(s.discoveryInterval.Load())
	if discoveryInterval == 0 {
		discoveryInterval = 30 * time.Minute
	}
	isOngoingEligible := !to.Before(now.Add(-discoveryInterval))

	for _, dev := range devList {
		records := recordsByDev[dev.id]

		// Prepend carry-in record if available and first record is after 'from' or no records in window
		if carry, ok := carryInByDev[dev.id]; ok {
			if len(records) == 0 {
				records = []model.DeviceScanRecord{carry}
			} else if records[0].RecordedAt.After(from) {
				records = append([]model.DeviceScanRecord{carry}, records...)
			}
		}

		var periods []model.TimelinePeriod

		if len(records) > 0 {
			var currentPeriod *model.TimelinePeriod
			var lastSampleTime time.Time

			for _, rec := range records {
				if currentPeriod == nil {
					currentPeriod = &model.TimelinePeriod{
						StartedAt:    rec.RecordedAt,
						EndedAt:      rec.RecordedAt,
						Status:       rec.Status,
						IsVulnerable: rec.IsVulnerable,
						VulnsCount:   rec.VulnsCount,
						MaxSeverity:  rec.MaxSeverity,
						IsOngoing:    false,
					}
					lastSampleTime = rec.RecordedAt
					continue
				}

				// Check for state shift
				stateChanged := (currentPeriod.Status != rec.Status) ||
					(currentPeriod.IsVulnerable != rec.IsVulnerable) ||
					(currentPeriod.MaxSeverity != rec.MaxSeverity)

				if stateChanged {
					// Close previous period k at StartedAt(k+1)
					currentPeriod.TransitionUncertaintyS = int64(rec.RecordedAt.Sub(lastSampleTime).Seconds())
					currentPeriod.EndedAt = rec.RecordedAt
					periods = append(periods, *currentPeriod)

					// Start new period k+1
					currentPeriod = &model.TimelinePeriod{
						StartedAt:    rec.RecordedAt,
						EndedAt:      rec.RecordedAt,
						Status:       rec.Status,
						IsVulnerable: rec.IsVulnerable,
						VulnsCount:   rec.VulnsCount,
						MaxSeverity:  rec.MaxSeverity,
						IsOngoing:    false,
					}
					lastSampleTime = rec.RecordedAt
				} else {
					// Extend current period
					currentPeriod.EndedAt = rec.RecordedAt
					lastSampleTime = rec.RecordedAt
					if rec.VulnsCount > currentPeriod.VulnsCount {
						currentPeriod.VulnsCount = rec.VulnsCount
					}
				}
			}

			if currentPeriod != nil {
				if isOngoingEligible && dev.status == currentPeriod.Status {
					currentPeriod.IsOngoing = true
					if to.After(currentPeriod.EndedAt) {
						currentPeriod.EndedAt = to
					}
				} else {
					currentPeriod.IsOngoing = false
					if to.After(currentPeriod.EndedAt) {
						currentPeriod.EndedAt = to
					}
				}
				periods = append(periods, *currentPeriod)
			}
		} else {
			// Fallback: If no granular scan records yet, synthesize period if first_seen/last_seen intersects window
			if !dev.lastSeen.Before(from) && !dev.firstSeen.After(to) {
				start := dev.firstSeen
				if start.Before(from) {
					start = from
				}
				end := dev.lastSeen
				if end.After(to) {
					end = to
				}

				isVuln, vulnsCount, maxSev, _ := s.GetDeviceSecurityPosture(ctx, dev.id)

				periods = append(periods, model.TimelinePeriod{
					StartedAt:    start,
					EndedAt:      end,
					Status:       dev.status,
					IsVulnerable: isVuln,
					VulnsCount:   vulnsCount,
					MaxSeverity:  maxSev,
					IsOngoing:    isOngoingEligible && dev.status == "up",
				})
			}
		}

		if periods == nil {
			periods = []model.TimelinePeriod{}
		}

		// If vulnerableOnly is set, check if any period has vulnerabilities
		if vulnerableOnly {
			hasVulnPeriod := false
			for _, p := range periods {
				if p.IsVulnerable {
					hasVulnPeriod = true
					break
				}
			}
			if !hasVulnPeriod {
				continue
			}
		}

		timelineDevices = append(timelineDevices, model.TimelineDevice{
			DeviceID:      dev.id,
			IP:            dev.ip,
			MAC:           dev.mac,
			Hostname:      dev.hostname,
			Vendor:        dev.vendor,
			CurrentStatus: dev.status,
			Periods:       periods,
		})
	}

	if timelineDevices == nil {
		timelineDevices = []model.TimelineDevice{}
	}

	return &model.TimelineResponse{
		TimeWindow: model.TimelineTimeWindow{
			From:         from,
			To:           to,
			TotalScans:   len(scanTicks),
			TotalDevices: len(timelineDevices),
		},
		ScanTicks: scanTicks,
		Devices:   timelineDevices,
	}, nil
}
