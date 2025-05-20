// Package datamodel defines the core data structures used throughout the
// gonetdisco application, including configuration structures parsed
// from YAML and the structures for storing discovery results.
package datamodel

// Config is the main configuration structure.
type Config struct {
	Targets            []TargetConfig      `yaml:"targets"`
	SNMPConfigs        []SNMPConfig        `yaml:"snmp_configs"`
	Profiles           []ProfileConfig     `yaml:"profiles"`
	GlobalScanSettings GlobalScanSettings  `yaml:"global_scan_settings"`
}

// GlobalScanSettings contains settings applicable to all scans.
type GlobalScanSettings struct {
	ConcurrentScanners     int      `yaml:"concurrent_scanners"`      // Number of goroutines for IP scanning
	DefaultOutputPath      string   `yaml:"default_output_path"`      // Default path for JSON output
	MaxOidsPerSNMPRequest  int      `yaml:"max_oids_per_snmp_request"`// Default 60, from gosnmp
	DefaultDNSServers      []string `yaml:"default_dns_servers,omitempty"` // Optional: list of DNS servers to use
}

// TargetConfig defines a set of addresses to be scanned with a specific profile.
type TargetConfig struct {
	Name        string   `yaml:"name"`        // Unique name for the target group
	Addresses   []string `yaml:"addresses"`   // e.g., "192.168.1.0/24", "10.0.0.5"
	ProfileName string   `yaml:"profile_name"`// Name of the profile to use for these addresses
}

// SNMPConfig defines a specific SNMP configuration to be used for querying devices.
type SNMPConfig struct {
	Name            string `yaml:"name"`           // Unique identifier for this SNMP configuration
	Version         string `yaml:"version"`        // "v1", "v2c", "v3"
	Community       string `yaml:"community,omitempty"` // For v1, v2c
	TimeoutSeconds  int    `yaml:"timeout_seconds"`// Per SNMP request
	Retries         int    `yaml:"retries"`        // Number of retries for an SNMP request

	// v3 specific parameters
	Username        string `yaml:"username,omitempty"`
	AuthProtocol    string `yaml:"auth_protocol,omitempty"`  // e.g., "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"
	AuthPassword    string `yaml:"auth_password,omitempty"`
	PrivProtocol    string `yaml:"priv_protocol,omitempty"`  // e.g., "DES", "AES", "AES192", "AES256"
	PrivPassword    string `yaml:"priv_password,omitempty"`
	SecurityLevel   string `yaml:"security_level,omitempty"` // "noAuthNoPriv", "authNoPriv", "authPriv"
	ContextName     string `yaml:"context_name,omitempty"`
}

// ProfileConfig defines a named profile that groups ICMP, SNMP, DNS, and TCP scanning parameters.
type ProfileConfig struct {
	Name    string      `yaml:"name"`   // Unique identifier for this profile
	ICMP    ICMPProfile `yaml:"icmp"`
	SNMP    SNMPProfile `yaml:"snmp"`
	DNS     DNSProfile  `yaml:"dns"`
	TCP     TCPProfile  `yaml:"tcp"`
}

// ICMPProfile contains parameters for ICMP scanning.
type ICMPProfile struct {
	IsEnabled         bool  `yaml:"is_enabled"`
	TimeoutSeconds    int   `yaml:"timeout_seconds"`    // Timeout per ping attempt
	Retries           int   `yaml:"retries"`            // Number of ping packets to send (Count in pro-bing)
	PacketSizeBytes   int   `yaml:"packet_size_bytes"`  // Size in pro-bing
	Privileged        bool  `yaml:"privileged"`         // Use raw sockets
	SkipIfUnreachable bool  `yaml:"skip_if_unreachable"`// Skip SNMP/DNS if ICMP unreachable, default true
}

// SNMPProfile contains parameters for SNMP scanning.
type SNMPProfile struct {
	IsEnabled          bool     `yaml:"is_enabled"`
	ConfigNamesOrdered []string `yaml:"config_names_ordered"` // List of SNMPConfig names to try in order
	OIDsToQuery        []string `yaml:"oids_to_query"`        // e.g., "1.3.6.1.2.1.1.1.0" (sysDescr)
}

// DNSProfile contains parameters for DNS lookups.
type DNSProfile struct {
	IsEnabled                     bool     `yaml:"is_enabled"`
	DoReverseLookup               bool     `yaml:"do_reverse_lookup"`
	DoForwardLookupIfReverseFound bool     `yaml:"do_forward_lookup_if_reverse_found"`
	TimeoutSeconds                int      `yaml:"timeout_seconds"` // Timeout for DNS queries
	DNSServers                    []string `yaml:"dns_servers,omitempty"` // Profile-specific DNS servers, overrides global
}

// TCPProfile contains parameters for TCP port scanning.
type TCPProfile struct {
	IsEnabled      bool  `yaml:"is_enabled"`
	TimeoutSeconds int   `yaml:"timeout_seconds"` // Timeout for TCP connection attempts
	Ports          []int `yaml:"ports"`           // List of ports to scan
}

// TCPConfig is used internally for passing TCP scanning parameters.
type TCPConfig struct {
	Enabled bool
	Timeout int
	Ports   []int
}

// Result Structures

// DiscoveredDevice represents a device found during the scan.
type DiscoveredDevice struct {
	IPAddress   string          `json:"ip_address"`
	TargetName  string          `json:"target_name"`    // From which TargetConfig this IP originated
	ProfileName string          `json:"profile_name"`   // Which profile was used
	ICMPResult  *ICMPScanResult `json:"icmp_result,omitempty"`
	SNMPResult  *SNMPScanResult `json:"snmp_result,omitempty"`
	DNSResult   *DNSScanResult  `json:"dns_result,omitempty"`
	TCPResult   *TCPScanResult  `json:"tcp_result,omitempty"`
	Timestamp   string          `json:"timestamp"`      // ISO8601 timestamp of discovery
	Errors      []string        `json:"errors,omitempty"` // Any errors encountered during scanning this device
}

// ICMPScanResult contains results from an ICMP scan attempt.
type ICMPScanResult struct {
	IsReachable        bool    `json:"is_reachable"`
	PacketsSent        int     `json:"packets_sent"`
	PacketsReceived    int     `json:"packets_received"`
	PacketLossPercent  float64 `json:"packet_loss_percent"`
	RTT_ms             float64 `json:"rtt_ms,omitempty"`
}

// SNMPScanResult contains results from an SNMP scan attempt.
type SNMPScanResult struct {
	SuccessfullyQueried bool                `json:"successfully_queried"`
	UsedSNMPConfigName  string              `json:"used_snmp_config_name"` // Which SNMPConfig succeeded
	QueriedData         map[string]SNMPValue `json:"queried_data,omitempty"` // OID -> Value
}

// SNMPValue represents a single value retrieved via SNMP.
type SNMPValue struct {
	Type    string      `json:"type"`   // e.g., "OctetString", "Integer", "Counter32"
	Value   interface{} `json:"value"`
	Error   string      `json:"error,omitempty"` // If a specific OID query failed
}

// DNSScanResult contains results from DNS lookup attempts.
type DNSScanResult struct {
	PTRRecords           []string            `json:"ptr_records,omitempty"` // Results of reverse lookup
	ForwardLookupResults map[string][]string `json:"forward_lookup_results,omitempty"` // hostname -> []IPs
	Errors               []string            `json:"errors,omitempty"` // Errors during DNS lookups
}

// TCPScanResult contains results from a TCP port scan.
type TCPScanResult struct {
	Reachable    bool           `json:"reachable"`      // At least one port is open
	OpenPorts    map[int]string `json:"open_ports"`     // Map of port numbers to service names
	ResponseTime float64        `json:"response_time,omitempty"` // Average response time in seconds
}

// Internal Structures

// ScanJob is an internal structure for managing scan jobs passed to worker goroutines.
type ScanJob struct {
	IPAddress    string
	TargetConfig TargetConfig
	Profile      ProfileConfig
	SNMPConfigs  map[string]SNMPConfig // Pre-resolved SNMP configs for this profile for quick access
}