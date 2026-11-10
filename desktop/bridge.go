package main

import (
	"context"

	"github.com/gr0gu/cerberus/internal/app"
	"github.com/gr0gu/cerberus/internal/model"
)

// Bridge connects the frontend UI to the Cerberus backend Daemon via Wails IPC.
type Bridge struct {
	d   *app.Daemon
	ctx context.Context
}

// NewBridge creates a new Bridge instance.
func NewBridge(d *app.Daemon) *Bridge {
	return &Bridge{d: d}
}

// SetContext sets the active Wails runtime context.
func (b *Bridge) SetContext(ctx context.Context) {
	b.ctx = ctx
}

// GetStatus returns the current live sentinel status for the UI.
func (b *Bridge) GetStatus() (model.SystemStatus, error) {
	return b.d.Status(), nil
}

// GetPosture returns the live fleet posture report.
func (b *Bridge) GetPosture() (*model.PostureReport, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.d.GetPosture(ctx)
}

// GetTimeline returns scan ticks and device activity periods for timeline rendering.
func (b *Bridge) GetTimeline(from, to, status string, vulnerableOnly bool) (*model.TimelineResponse, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.d.GetTimeline(ctx, from, to, status, vulnerableOnly)
}

// GetDevices returns all tracked devices, with an optional "up"/"down" status filter.
func (b *Bridge) GetDevices(status string) (map[string]any, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	devs, err := b.d.GetDevices(ctx, status)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"count":   len(devs),
		"devices": devs,
	}, nil
}

// GetDeviceByID returns detailed device info including open services and CVEs.
func (b *Bridge) GetDeviceByID(id int64) (*model.Device, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.d.GetDeviceByID(ctx, id)
}

// UpdateDevice updates editable fields (label, criticality, notes) on a device.
func (b *Bridge) UpdateDevice(id int64, label, criticality, notes *string) (*model.Device, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req := model.UpdateDeviceRequest{
		Label:       label,
		Criticality: criticality,
		Notes:       notes,
	}
	return b.d.UpdateDevice(ctx, id, req)
}

// DeleteDevice removes a device from tracking.
func (b *Bridge) DeleteDevice(id int64) (map[string]string, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := b.d.DeleteDevice(ctx, id); err != nil {
		return nil, err
	}
	return map[string]string{"status": "deleted"}, nil
}

// ClearAllDevices deletes all devices and their dependent items.
func (b *Bridge) ClearAllDevices() (map[string]any, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	count, err := b.d.ClearAllDevices(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": "cleared", "deleted": count}, nil
}

// ClearScanHistory deletes all scan execution records.
func (b *Bridge) ClearScanHistory() (map[string]any, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	count, err := b.d.ClearScanHistory(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": "cleared", "deleted": count}, nil
}

// DeleteService deletes a single service and associated findings.
func (b *Bridge) DeleteService(id int64) (map[string]string, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := b.d.DeleteService(ctx, id); err != nil {
		return nil, err
	}
	return map[string]string{"status": "deleted"}, nil
}

// DeleteVulnerability deletes a single vulnerability finding.
func (b *Bridge) DeleteVulnerability(id int64) (map[string]string, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := b.d.DeleteVulnerability(ctx, id); err != nil {
		return nil, err
	}
	return map[string]string{"status": "deleted"}, nil
}

// GetServices returns all services detected across the network.
func (b *Bridge) GetServices() (map[string]any, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	svcs, err := b.d.GetServices(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"count":    len(svcs),
		"services": svcs,
	}, nil
}

// GetVulnerabilities returns all detected vulnerabilities.
func (b *Bridge) GetVulnerabilities(severity string) (map[string]any, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	vulns, err := b.d.GetVulnerabilities(ctx, severity)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"count":           len(vulns),
		"vulnerabilities": vulns,
	}, nil
}

// GetScans returns recent scan history.
func (b *Bridge) GetScans(limit int) (map[string]any, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	scans, err := b.d.GetScans(ctx, limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"count": len(scans),
		"scans": scans,
	}, nil
}

// TriggerDiscovery initiates an immediate host discovery sweep.
// A scan of the same type that is already running reports status "conflict".
func (b *Bridge) TriggerDiscovery() (map[string]string, error) {
	return b.requestScan("discovery")
}

// TriggerVulnerabilityScan initiates an immediate vulnerability audit.
func (b *Bridge) TriggerVulnerabilityScan() (map[string]string, error) {
	return b.requestScan("vulnerability")
}

// CancelScan terminates the active network scan immediately without orphan processes.
func (b *Bridge) CancelScan() (map[string]string, error) {
	if b.d.CancelScan() {
		return map[string]string{"status": "cancelled"}, nil
	}
	return map[string]string{"status": "idle"}, nil
}

func (b *Bridge) requestScan(scanType string) (map[string]string, error) {
	result := b.d.RequestScan(scanType)
	body := map[string]string{
		"status":    result.Status,
		"scan_type": result.ScanType,
	}
	if result.Message != "" {
		body["message"] = result.Message
	}
	if result.Error != "" {
		body["error"] = result.Error
	}
	return body, nil
}

// GetLogs returns the recent lines of the daemon log, oldest first. New lines are sent
// as "cerberus:log" events.
func (b *Bridge) GetLogs() (map[string]any, error) {
	entries := b.d.Logs()
	return map[string]any{
		"count": len(entries),
		"logs":  entries,
	}, nil
}

// GetSettings retrieves current application settings, available network interfaces, and scanner capabilities.
func (b *Bridge) GetSettings() (*model.SettingsResponse, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.d.GetSettings(ctx)
}

// UpdateSettings updates application settings, persists them in SQLite, and hot-reloads the scanner.
func (b *Bridge) UpdateSettings(req model.AppSettings) (*model.SettingsResponse, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.d.UpdateSettings(ctx, req)
}

// SetupNmapAndPrivileges triggers OS native privilege elevation or installer setup.
func (b *Bridge) SetupNmapAndPrivileges() (*model.Capabilities, error) {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return b.d.SetupNmapAndPrivileges(ctx)
}
