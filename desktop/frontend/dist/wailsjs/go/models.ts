export namespace model {
	
	export class AppSettings {
	    network_mode: string;
	    selected_interface: string;
	    custom_network_cidr: string;
	    effective_cidr: string;
	    effective_exclude_ip: string;
	    scan_ports: string;
	    discovery_interval_sec: number;
	    vuln_interval_sec: number;
	    nmap_path: string;
	
	    static createFrom(source: any = {}) {
	        return new AppSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.network_mode = source["network_mode"];
	        this.selected_interface = source["selected_interface"];
	        this.custom_network_cidr = source["custom_network_cidr"];
	        this.effective_cidr = source["effective_cidr"];
	        this.effective_exclude_ip = source["effective_exclude_ip"];
	        this.scan_ports = source["scan_ports"];
	        this.discovery_interval_sec = source["discovery_interval_sec"];
	        this.vuln_interval_sec = source["vuln_interval_sec"];
	        this.nmap_path = source["nmap_path"];
	    }
	}
	export class Capabilities {
	    nmap_path: string;
	    nmap_version: string;
	    vuln_script_ok: boolean;
	    raw_socket: boolean;
	    effective_mode: string;
	    warnings?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Capabilities(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.nmap_path = source["nmap_path"];
	        this.nmap_version = source["nmap_version"];
	        this.vuln_script_ok = source["vuln_script_ok"];
	        this.raw_socket = source["raw_socket"];
	        this.effective_mode = source["effective_mode"];
	        this.warnings = source["warnings"];
	    }
	}
	export class Vulnerability {
	    id: number;
	    device_id: number;
	    device_ip?: string;
	    service_port: number;
	    cve_id: string;
	    title?: string;
	    severity: string;
	    cvss_score: number;
	    description?: string;
	    reference_url?: string;
	    // Go type: time
	    detected_at: any;
	    status: string;
	    // Go type: time
	    first_detected_at: any;
	    // Go type: time
	    last_seen_at: any;
	    // Go type: time
	    resolved_at?: any;
	
	    static createFrom(source: any = {}) {
	        return new Vulnerability(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.device_id = source["device_id"];
	        this.device_ip = source["device_ip"];
	        this.service_port = source["service_port"];
	        this.cve_id = source["cve_id"];
	        this.title = source["title"];
	        this.severity = source["severity"];
	        this.cvss_score = source["cvss_score"];
	        this.description = source["description"];
	        this.reference_url = source["reference_url"];
	        this.detected_at = this.convertValues(source["detected_at"], null);
	        this.status = source["status"];
	        this.first_detected_at = this.convertValues(source["first_detected_at"], null);
	        this.last_seen_at = this.convertValues(source["last_seen_at"], null);
	        this.resolved_at = this.convertValues(source["resolved_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Service {
	    id: number;
	    device_id: number;
	    device_ip?: string;
	    port: number;
	    protocol: string;
	    service_name?: string;
	    product?: string;
	    version?: string;
	    state: string;
	    // Go type: time
	    updated_at: any;
	    vulnerabilities?: Vulnerability[];
	
	    static createFrom(source: any = {}) {
	        return new Service(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.device_id = source["device_id"];
	        this.device_ip = source["device_ip"];
	        this.port = source["port"];
	        this.protocol = source["protocol"];
	        this.service_name = source["service_name"];
	        this.product = source["product"];
	        this.version = source["version"];
	        this.state = source["state"];
	        this.updated_at = this.convertValues(source["updated_at"], null);
	        this.vulnerabilities = this.convertValues(source["vulnerabilities"], Vulnerability);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Device {
	    id: number;
	    current_ip: string;
	    ip: string;
	    mac?: string;
	    hostname?: string;
	    vendor?: string;
	    status: string;
	    // Go type: time
	    first_seen: any;
	    // Go type: time
	    last_seen: any;
	    asset_uid: string;
	    mac_is_random: boolean;
	    port_profile_hash?: string;
	    fingerprints?: string[];
	    managed: boolean;
	    identity_confidence: number;
	    label?: string;
	    criticality: string;
	    notes?: string;
	    risk?: number;
	    score?: number;
	    services_count: number;
	    vulnerabilities_count: number;
	    services?: Service[];
	    vulnerabilities?: Vulnerability[];
	
	    static createFrom(source: any = {}) {
	        return new Device(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.current_ip = source["current_ip"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.hostname = source["hostname"];
	        this.vendor = source["vendor"];
	        this.status = source["status"];
	        this.first_seen = this.convertValues(source["first_seen"], null);
	        this.last_seen = this.convertValues(source["last_seen"], null);
	        this.asset_uid = source["asset_uid"];
	        this.mac_is_random = source["mac_is_random"];
	        this.port_profile_hash = source["port_profile_hash"];
	        this.fingerprints = source["fingerprints"];
	        this.managed = source["managed"];
	        this.identity_confidence = source["identity_confidence"];
	        this.label = source["label"];
	        this.criticality = source["criticality"];
	        this.notes = source["notes"];
	        this.risk = source["risk"];
	        this.score = source["score"];
	        this.services_count = source["services_count"];
	        this.vulnerabilities_count = source["vulnerabilities_count"];
	        this.services = this.convertValues(source["services"], Service);
	        this.vulnerabilities = this.convertValues(source["vulnerabilities"], Vulnerability);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DevicePostureSummary {
	    device_id: number;
	    current_ip: string;
	    hostname?: string;
	    managed: boolean;
	    risk: number;
	    score: number;
	    open_vulns: number;
	    max_cve: number;
	
	    static createFrom(source: any = {}) {
	        return new DevicePostureSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device_id = source["device_id"];
	        this.current_ip = source["current_ip"];
	        this.hostname = source["hostname"];
	        this.managed = source["managed"];
	        this.risk = source["risk"];
	        this.score = source["score"];
	        this.open_vulns = source["open_vulns"];
	        this.max_cve = source["max_cve"];
	    }
	}
	export class NetworkInterfaceInfo {
	    name: string;
	    ipv4: string;
	    cidr: string;
	    mac: string;
	    is_default: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NetworkInterfaceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.ipv4 = source["ipv4"];
	        this.cidr = source["cidr"];
	        this.mac = source["mac"];
	        this.is_default = source["is_default"];
	    }
	}
	export class PostureReport {
	    // Go type: time
	    computed_at: any;
	    policy_version: string;
	    fleet_score?: number;
	    posture_status?: string;
	    active_devices: number;
	    mean_risk: number;
	    max_risk: number;
	    penalty_total: number;
	    device_scores: DevicePostureSummary[];
	
	    static createFrom(source: any = {}) {
	        return new PostureReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.computed_at = this.convertValues(source["computed_at"], null);
	        this.policy_version = source["policy_version"];
	        this.fleet_score = source["fleet_score"];
	        this.posture_status = source["posture_status"];
	        this.active_devices = source["active_devices"];
	        this.mean_risk = source["mean_risk"];
	        this.max_risk = source["max_risk"];
	        this.penalty_total = source["penalty_total"];
	        this.device_scores = this.convertValues(source["device_scores"], DevicePostureSummary);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ScanTick {
	    scan_id: number;
	    // Go type: time
	    timestamp: any;
	    scan_type: string;
	    status: string;
	    target_spec: string;
	    hosts_found: number;
	    duration_ms: number;
	
	    static createFrom(source: any = {}) {
	        return new ScanTick(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.scan_id = source["scan_id"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.scan_type = source["scan_type"];
	        this.status = source["status"];
	        this.target_spec = source["target_spec"];
	        this.hosts_found = source["hosts_found"];
	        this.duration_ms = source["duration_ms"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class SettingsResponse {
	    settings: AppSettings;
	    interfaces: NetworkInterfaceInfo[];
	    capabilities?: Capabilities;
	
	    static createFrom(source: any = {}) {
	        return new SettingsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.settings = this.convertValues(source["settings"], AppSettings);
	        this.interfaces = this.convertValues(source["interfaces"], NetworkInterfaceInfo);
	        this.capabilities = this.convertValues(source["capabilities"], Capabilities);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SystemStatus {
	    uptime: string;
	    uptime_seconds: number;
	    active_devices: number;
	    total_devices: number;
	    total_services: number;
	    total_vulnerabilities: number;
	    // Go type: time
	    discovery_next_run?: any;
	    // Go type: time
	    vuln_next_run?: any;
	    is_discovery_running: boolean;
	    is_vuln_running: boolean;
	    capabilities?: Capabilities;
	    ingest_events_total: number;
	    detect_lag_ms_p95: number;
	    incidents_open: number;
	    fleet_score?: number;
	    posture_status?: string;
	
	    static createFrom(source: any = {}) {
	        return new SystemStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.uptime = source["uptime"];
	        this.uptime_seconds = source["uptime_seconds"];
	        this.active_devices = source["active_devices"];
	        this.total_devices = source["total_devices"];
	        this.total_services = source["total_services"];
	        this.total_vulnerabilities = source["total_vulnerabilities"];
	        this.discovery_next_run = this.convertValues(source["discovery_next_run"], null);
	        this.vuln_next_run = this.convertValues(source["vuln_next_run"], null);
	        this.is_discovery_running = source["is_discovery_running"];
	        this.is_vuln_running = source["is_vuln_running"];
	        this.capabilities = this.convertValues(source["capabilities"], Capabilities);
	        this.ingest_events_total = source["ingest_events_total"];
	        this.detect_lag_ms_p95 = source["detect_lag_ms_p95"];
	        this.incidents_open = source["incidents_open"];
	        this.fleet_score = source["fleet_score"];
	        this.posture_status = source["posture_status"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TimelinePeriod {
	    // Go type: time
	    started_at: any;
	    // Go type: time
	    ended_at: any;
	    status: string;
	    is_vulnerable: boolean;
	    vulns_count: number;
	    max_severity: string;
	    is_ongoing: boolean;
	    transition_uncertainty_s?: number;
	
	    static createFrom(source: any = {}) {
	        return new TimelinePeriod(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.started_at = this.convertValues(source["started_at"], null);
	        this.ended_at = this.convertValues(source["ended_at"], null);
	        this.status = source["status"];
	        this.is_vulnerable = source["is_vulnerable"];
	        this.vulns_count = source["vulns_count"];
	        this.max_severity = source["max_severity"];
	        this.is_ongoing = source["is_ongoing"];
	        this.transition_uncertainty_s = source["transition_uncertainty_s"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TimelineDevice {
	    device_id: number;
	    ip: string;
	    mac?: string;
	    hostname?: string;
	    vendor?: string;
	    current_status: string;
	    periods: TimelinePeriod[];
	
	    static createFrom(source: any = {}) {
	        return new TimelineDevice(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device_id = source["device_id"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.hostname = source["hostname"];
	        this.vendor = source["vendor"];
	        this.current_status = source["current_status"];
	        this.periods = this.convertValues(source["periods"], TimelinePeriod);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class TimelineTimeWindow {
	    // Go type: time
	    from: any;
	    // Go type: time
	    to: any;
	    total_scans: number;
	    total_devices: number;
	
	    static createFrom(source: any = {}) {
	        return new TimelineTimeWindow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = this.convertValues(source["from"], null);
	        this.to = this.convertValues(source["to"], null);
	        this.total_scans = source["total_scans"];
	        this.total_devices = source["total_devices"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TimelineResponse {
	    time_window: TimelineTimeWindow;
	    scan_ticks: ScanTick[];
	    devices: TimelineDevice[];
	
	    static createFrom(source: any = {}) {
	        return new TimelineResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time_window = this.convertValues(source["time_window"], TimelineTimeWindow);
	        this.scan_ticks = this.convertValues(source["scan_ticks"], ScanTick);
	        this.devices = this.convertValues(source["devices"], TimelineDevice);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

