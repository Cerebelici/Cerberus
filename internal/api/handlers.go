package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/logstream"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scheduler"
)

// handleGetDevices returns all tracked devices, with optional ?status=up|down filter.
func (s *Server) handleGetDevices(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")

	devices, err := s.storage.GetDevices(r.Context(), statusFilter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if devices == nil {
		devices = []model.Device{}
	}

	if s.postureService != nil {
		report, err := s.postureService.Compute(r.Context())
		if err == nil && report != nil {
			riskMap := make(map[int64]model.DevicePostureSummary, len(report.DeviceScores))
			for _, ds := range report.DeviceScores {
				riskMap[ds.DeviceID] = ds
			}
			for i := range devices {
				if ds, ok := riskMap[devices[i].ID]; ok {
					devices[i].Risk = ds.Risk
					devices[i].Score = ds.Score
				} else {
					devices[i].Risk = 0.0
					devices[i].Score = 100.0
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(devices),
		"devices": devices,
	})
}

// handleGetDeviceByID returns detailed device info including open services and CVEs.
func (s *Server) handleGetDeviceByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	device, err := s.storage.GetDeviceByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if device == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("device %d not found", id)})
		return
	}

	if s.postureService != nil {
		report, err := s.postureService.Compute(r.Context())
		if err == nil && report != nil {
			found := false
			for _, ds := range report.DeviceScores {
				if ds.DeviceID == device.ID {
					device.Risk = ds.Risk
					device.Score = ds.Score
					found = true
					break
				}
			}
			if !found {
				device.Risk = 0.0
				device.Score = 100.0
			}
		}
	}

	writeJSON(w, http.StatusOK, device)
}

// handlePatchDevice updates editable fields (label, criticality, notes) on a device.
func (s *Server) handlePatchDevice(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	var req model.UpdateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	dev, err := s.storage.UpdateDeviceFields(r.Context(), id, req.Label, req.Criticality, req.Notes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("device %d not found", id)})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, dev)
}

// handleMergeDevice merges a source device into the target device.
func (s *Server) handleMergeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	idStr := r.PathValue("id")
	targetID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	var req model.MergeDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	if req.SourceID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source_id is required"})
		return
	}

	if err := s.storage.MergeDevices(r.Context(), targetID, req.SourceID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	dev, _ := s.storage.GetDeviceByID(r.Context(), targetID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "merged",
		"target": dev,
	})
}

// handleSplitDevice splits an address lease off to create a new device entity.
func (s *Server) handleSplitDevice(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	idStr := r.PathValue("id")
	deviceID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	var req model.SplitDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	if req.AddressID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "address_id is required"})
		return
	}

	newDev, err := s.storage.SplitDevice(r.Context(), deviceID, req.AddressID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, newDev)
}

// handleDeleteDevice deletes a device entity.
func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	idStr := r.PathValue("id")
	deviceID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	if err := s.storage.DeleteDevice(r.Context(), deviceID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("device %d not found", deviceID)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleClearAllDevices purges all devices and dependent child records.
func (s *Server) handleClearAllDevices(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	count, err := s.storage.ClearAllDevices(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared", "deleted": count})
}

// handleClearScanHistory purges all historical scan execution logs.
func (s *Server) handleClearScanHistory(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	count, err := s.storage.ClearScanHistory(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared", "deleted": count})
}

// handleDeleteService deletes a single service entity.
func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	idStr := r.PathValue("id")
	serviceID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service id"})
		return
	}

	if err := s.storage.DeleteService(r.Context(), serviceID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("service %d not found", serviceID)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleDeleteVulnerability deletes a single vulnerability entity.
func (s *Server) handleDeleteVulnerability(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}

	idStr := r.PathValue("id")
	vulnID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid vulnerability id"})
		return
	}

	if err := s.storage.DeleteVulnerability(r.Context(), vulnID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("vulnerability %d not found", vulnID)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleGetDeviceIdentity returns identity resolution decision logs for a device.
func (s *Server) handleGetDeviceIdentity(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	deviceID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}

	decisions, err := s.storage.GetDeviceIdentityDecisions(r.Context(), deviceID, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(decisions),
		"decisions": decisions,
	})
}

// handleGetDeviceAddresses returns address lease history for a device.
func (s *Server) handleGetDeviceAddresses(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	deviceID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device id"})
		return
	}

	addresses, err := s.storage.GetDeviceAddresses(r.Context(), deviceID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(addresses),
		"addresses": addresses,
	})
}

// handleGetServices returns all services detected across the entire network.
func (s *Server) handleGetServices(w http.ResponseWriter, r *http.Request) {
	services, err := s.storage.GetAllServices(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if services == nil {
		services = []model.Service{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":    len(services),
		"services": services,
	})
}

// handleGetVulnerabilities returns all detected vulnerabilities, with optional ?severity=CRITICAL filter.
func (s *Server) handleGetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")

	vulns, err := s.storage.GetAllVulnerabilities(r.Context(), severity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if vulns == nil {
		vulns = []model.Vulnerability{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":           len(vulns),
		"vulnerabilities": vulns,
	})
}

// handleGetScans returns recent scan execution history.
func (s *Server) handleGetScans(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	scans, err := s.storage.GetRecentScans(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if scans == nil {
		scans = []model.ScanLog{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(scans),
		"scans": scans,
	})
}

// handleTriggerDiscovery launches an immediate network discovery scan.
func (s *Server) handleTriggerDiscovery(w http.ResponseWriter, r *http.Request) {
	s.dispatchManualScan(w, ScanTypeDiscovery)
}

// handleTriggerVuln launches an immediate vulnerability scan across active devices.
func (s *Server) handleTriggerVuln(w http.ResponseWriter, r *http.Request) {
	s.dispatchManualScan(w, ScanTypeVulnerability)
}

// Scan types an operator can trigger manually.
const (
	ScanTypeDiscovery     = "discovery"
	ScanTypeVulnerability = "vulnerability"
)

// ManualScanResult is the outcome of a manual scan request, shared by the HTTP API and the
// desktop IPC bridge so both report the same contract.
type ManualScanResult struct {
	HTTPStatus int               // 202 accepted, 409 already in progress, 503 no scheduler
	Body       map[string]string // message/status/scan_type, or error/status/scan_type
}

// RequestManualScan hands a manual scan to the scheduler worker without waiting for it.
// Clients follow the outcome through GET /api/status (is_*_running) and GET /api/scans.
func RequestManualScan(sched *scheduler.Scheduler, scanType string) ManualScanResult {
	if sched == nil {
		return ManualScanResult{http.StatusServiceUnavailable, map[string]string{
			"error":     "scan scheduler is not available",
			"status":    "unavailable",
			"scan_type": scanType,
		}}
	}

	request, message := sched.RequestDiscovery, "Discovery scan initiated in background"
	if scanType == ScanTypeVulnerability {
		request, message = sched.RequestVulnerabilityScan, "Vulnerability audit initiated in background"
	}
	if err := request(); err != nil {
		return ManualScanResult{http.StatusConflict, map[string]string{
			"error":     fmt.Sprintf("A %s scan is already in progress", scanType),
			"status":    "conflict",
			"scan_type": scanType,
		}}
	}
	return ManualScanResult{http.StatusAccepted, map[string]string{
		"message":   message,
		"status":    "running",
		"scan_type": scanType,
	}}
}

func (s *Server) dispatchManualScan(w http.ResponseWriter, scanType string) {
	if s.capabilities != nil && !s.capabilities.RawSocket && s.capabilities.EffectiveMode != "privileged" {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":     "Privileged execution is mandatory. User must accept administrator privileges to perform network scans.",
			"status":    "forbidden",
			"scan_type": scanType,
		})
		return
	}
	result := RequestManualScan(s.scheduler, scanType)
	writeJSON(w, result.HTTPStatus, result.Body)
}

// handleGetLogs returns the recent lines of the daemon log.
func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	entries := []logstream.Entry{}
	if s.logs != nil {
		entries = s.logs.Entries()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(entries),
		"logs":  entries,
	})
}

// handleGetSettings returns the active settings, network interfaces and scanner capabilities.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "settings are not available"})
		return
	}
	resp, err := s.settings.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleUpdateSettings saves new settings and applies them to the running scanner.
func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedForMutation(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: loopback or API key required"})
		return
	}
	if s.settings == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "settings are not available"})
		return
	}
	var req model.AppSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	resp, err := s.settings.UpdateSettings(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetStatus evaluates and returns the full system status metrics.
func (s *Server) GetStatus(ctx context.Context) (model.SystemStatus, error) {
	totalDevs, activeDevs, totalSvcs, totalVulns, err := s.storage.GetCounts(ctx)
	if err != nil {
		return model.SystemStatus{}, err
	}

	uptimeDuration := time.Since(s.startTime)
	var discNext, vulnNext *time.Time
	var discRunning, vulnRunning bool
	if s.scheduler != nil {
		discNext, vulnNext, discRunning, vulnRunning = s.scheduler.GetNextRuns()
	}

	caps := s.capabilities
	if caps == nil {
		caps = &model.Capabilities{
			NmapPath:      s.cfg.NmapPath,
			EffectiveMode: "unprivileged",
		}
	}

	status := model.SystemStatus{
		Uptime:               uptimeDuration.Round(time.Second).String(),
		UptimeSeconds:        int64(uptimeDuration.Seconds()),
		TotalDevices:         totalDevs,
		ActiveDevices:        activeDevs,
		TotalServices:        totalSvcs,
		TotalVulnerabilities: totalVulns,
		DiscoveryNextRun:     discNext,
		VulnNextRun:          vulnNext,
		IsDiscoveryRunning:   discRunning,
		IsVulnRunning:        vulnRunning,
		Capabilities:         caps,
	}

	if s.engine != nil {
		status.IngestEventsTotal = s.engine.IngestEventsTotal()
		status.DetectLagMsP95 = s.engine.DetectLagMsP95()
		status.IncidentsOpen = s.engine.OpenIncidentsCount(ctx)
	}

	if s.postureService != nil {
		report, err := s.postureService.Compute(ctx)
		if err == nil && report != nil {
			status.FleetScore = report.FleetScore
			status.PostureStatus = report.PostureStatus
		}
	}

	return status, nil
}

// handleGetStatus returns system health, uptime, counts, and scheduler state.
func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.GetStatus(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// handleExportJSON returns the full network sentinel dataset formatted as JSON.
func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	cidr := s.cfg.NetworkCIDR
	if s.scheduler != nil {
		cidr = s.scheduler.DiscoveryTarget()
	}
	data, err := s.storage.ExportAllData(r.Context(), cidr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"cerberus-export-%s.json\"", time.Now().Format("20060102-150405")))
	writeJSON(w, http.StatusOK, data)
}

// handleGetTimeline returns scan ticks and device activity periods for frontend timeline rendering.
func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	to := now

	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if parsedTo, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = parsedTo.UTC()
		}
	}

	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if parsedFrom, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = parsedFrom.UTC()
		} else if dur, err := time.ParseDuration(fromStr); err == nil {
			from = to.Add(-dur)
		}
	}

	statusFilter := r.URL.Query().Get("status")
	vulnOnlyStr := r.URL.Query().Get("vulnerable_only")
	if vulnOnlyStr == "" {
		vulnOnlyStr = r.URL.Query().Get("vulnerable")
	}
	vulnerableOnly := vulnOnlyStr == "true" || vulnOnlyStr == "1"

	timeline, err := s.storage.GetTimeline(r.Context(), from, to, statusFilter, vulnerableOnly)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, timeline)
}

// handleGetIncidents retrieves security incidents filtered by query parameters.
func (s *Server) handleGetIncidents(w http.ResponseWriter, r *http.Request) {
	filter := model.IncidentFilter{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
	}

	if devIDStr := r.URL.Query().Get("device_id"); devIDStr != "" {
		if id, err := strconv.ParseInt(devIDStr, 10, 64); err == nil {
			filter.DeviceID = &id
		}
	}
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			tUTC := t.UTC()
			filter.From = &tUTC
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			tUTC := t.UTC()
			filter.To = &tUTC
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if lim, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = lim
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if off, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = off
		}
	}

	incidents, err := s.storage.GetIncidents(r.Context(), filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, incidents)
}

// handleGetIncidentByID retrieves details for a single incident, including evidence event records.
func (s *Server) handleGetIncidentByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			idStr = parts[2]
		}
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid incident id"})
		return
	}

	inc, err := s.storage.GetIncidentByID(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, inc)
}

// handlePatchIncident updates an incident's triage status (open, acknowledged, closed).
func (s *Server) handlePatchIncident(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			idStr = parts[2]
		}
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid incident id"})
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	req.Status = strings.ToLower(strings.TrimSpace(req.Status))
	if req.Status != "open" && req.Status != "acknowledged" && req.Status != "closed" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of: open, acknowledged, closed"})
		return
	}

	if err := s.storage.UpdateIncidentStatus(r.Context(), id, req.Status); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	inc, err := s.storage.GetIncidentByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"id": id, "status": req.Status})
		return
	}

	writeJSON(w, http.StatusOK, inc)
}

// handleGetPosture returns the live fleet posture report (cached for 30 seconds).
func (s *Server) handleGetPosture(w http.ResponseWriter, r *http.Request) {
	if s.postureService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "posture service not configured"})
		return
	}

	report, err := s.postureService.Compute(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// handleGetPostureHistory returns historical snapshots filtered by ?from=...&to=...
func (s *Server) handleGetPostureHistory(w http.ResponseWriter, r *http.Request) {
	if s.postureService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "posture service not configured"})
		return
	}

	var from, to time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid from timestamp, must be RFC3339 format"})
			return
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid to timestamp, must be RFC3339 format"})
			return
		}
	}

	history, err := s.postureService.GetHistory(r.Context(), from, to)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if history == nil {
		history = []model.PostureSnapshot{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(history),
		"snapshots": history,
	})
}
