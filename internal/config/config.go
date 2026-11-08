package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// Config holds all runtime configuration for Cerberus Sentinel.
type Config struct {
	ServerHost            string
	ServerPort            int
	DBPath                string
	NetworkCIDR           string
	DiscoveryInterval     time.Duration
	VulnerabilityInterval time.Duration
	NmapPath              string
	VulnScript            string
	ScanTimeout           time.Duration
	EnrollToken           string
	IngestMaxBody         int64
	IngestShards          int
	EventRetention        time.Duration
	APIKey                string
	ScanPorts             string
	ImmediateScanDelay    time.Duration
	DisableHTTPServer     bool
	AutoDetectNetwork     bool

	ActiveUsersHost  string
	EnableTracking   bool
	TrackingKey      string
	AppVersion       string
	ClientID         string
	TrackingInterval time.Duration
}

// OSDataDir returns an OS-appropriate writable data directory for persistent app files (e.g. SQLite database).
func OSDataDir(appName, fileName string) string {
	var baseDir string
	switch runtime.GOOS {
	case "windows":
		baseDir = os.Getenv("APPDATA")
		if baseDir == "" {
			baseDir = os.Getenv("USERPROFILE")
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err == nil {
			baseDir = filepath.Join(home, "Library", "Application Support")
		}
	default: // Linux and others
		baseDir = os.Getenv("XDG_DATA_HOME")
		if baseDir == "" {
			home, err := os.UserHomeDir()
			if err == nil {
				baseDir = filepath.Join(home, ".local", "share")
			}
		}
	}

	if baseDir == "" {
		baseDir = "."
	}

	appDir := filepath.Join(baseDir, appName)
	_ = os.MkdirAll(appDir, 0755)
	if fileName == "" {
		return appDir
	}
	return filepath.Join(appDir, fileName)
}

// Load returns configuration populated with defaults and overridden by environment variables.
func Load() *Config {
	subnetEnv, hasSubnet := os.LookupEnv("CERBERUS_SUBNET")
	autoDetect := !hasSubnet

	cfg := &Config{
		ServerHost:            getEnv("CERBERUS_HOST", "0.0.0.0"),
		ServerPort:            getEnvInt("CERBERUS_PORT", 8080),
		DBPath:                getEnv("CERBERUS_DB_PATH", "cerberus.db"),
		NetworkCIDR:           subnetEnv,
		DiscoveryInterval:     getEnvDuration("CERBERUS_DISCOVERY_INTERVAL", 5*time.Minute),
		VulnerabilityInterval: getEnvDuration("CERBERUS_VULN_INTERVAL", 5*time.Minute),
		NmapPath:              getEnv("CERBERUS_NMAP_PATH", "nmap"),
		VulnScript:            getEnv("CERBERUS_VULN_SCRIPT", "vulners"),
		ScanTimeout:           getEnvDuration("CERBERUS_SCAN_TIMEOUT", 15*time.Minute),
		EnrollToken:           getEnv("CERBERUS_ENROLL_TOKEN", ""),
		IngestMaxBody:         getEnvInt64("CERBERUS_INGEST_MAX_BODY", 1048576),
		IngestShards:          getEnvInt("CERBERUS_INGEST_SHARDS", runtime.GOMAXPROCS(0)),
		EventRetention:        getEnvDuration("CERBERUS_EVENT_RETENTION", 168*time.Hour),
		APIKey:                getEnv("CERBERUS_API_KEY", ""),
		ScanPorts:             getEnv("CERBERUS_SCAN_PORTS", ""),
		ImmediateScanDelay:    getEnvDuration("CERBERUS_IMMEDIATE_DELAY", 3*time.Second),
		DisableHTTPServer:     getEnvBool("CERBERUS_DISABLE_HTTP", false),
		AutoDetectNetwork:     autoDetect,

		ActiveUsersHost:  getEnv("ACTIVE_USERS_HOST_ENDPOINT", ""),
		EnableTracking:   getEnvBool("ENABLE_TRACKING", true),
		TrackingKey:      getEnv("TRACKING_KEY", "67676767676767676767676767"),
		AppVersion:       getEnv("CERBERUS_APP_VERSION", "0.1.0"),
		ClientID:         getEnv("CERBERUS_CLIENT_ID", ""),
		TrackingInterval: getEnvDuration("CERBERUS_TRACKING_INTERVAL", 24*time.Hour),
	}

	if cfg.NetworkCIDR == "" && !autoDetect {
		cfg.NetworkCIDR = "172.28.0.0/24"
	}

	return cfg
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvInt64(key string, defaultVal int64) int64 {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultVal
}
