// Package config is responsible for loading the YAML configuration file,
// unmarshalling it into the structures defined in the datamodel module,
// and performing validation to ensure the configuration is semantically correct.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/lukeod/gonetdisco/datamodel"
	"gopkg.in/yaml.v3"
)

// LoadConfig loads and validates the configuration from a YAML file.
func LoadConfig(filePath string) (*datamodel.Config, error) {
	// Read the YAML file
	yamlFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file %s: %w", filePath, err)
	}

	// Unmarshal YAML into Config struct
	var config datamodel.Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling YAML from %s: %w", filePath, err)
	}

	// Validate the loaded configuration
	err = validateConfig(&config)
	if err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set defaults if not provided
	setDefaults(&config)

	return &config, nil
}

// setDefaults applies default values to the configuration where not specified.
func setDefaults(cfg *datamodel.Config) {
	// Global scan settings defaults
	if cfg.GlobalScanSettings.MaxOidsPerSNMPRequest == 0 {
		cfg.GlobalScanSettings.MaxOidsPerSNMPRequest = 60 // Default from gosnmp
	}
	if cfg.GlobalScanSettings.ConcurrentScanners == 0 {
		cfg.GlobalScanSettings.ConcurrentScanners = 10 // A sensible default
	}
	if cfg.GlobalScanSettings.DefaultOutputPath == "" {
		cfg.GlobalScanSettings.DefaultOutputPath = "./discovered_devices.json"
	}

	// Set default for SkipIfUnreachable in ICMP profiles if not explicitly set
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ICMP.IsEnabled && !cfg.Profiles[i].ICMP.SkipIfUnreachable {
			// Default to true - skip additional tasks if IP doesn't respond to ping
			cfg.Profiles[i].ICMP.SkipIfUnreachable = true
		}

		// Set default timeout for TCP scanning if not specified
		if cfg.Profiles[i].TCP.IsEnabled && cfg.Profiles[i].TCP.TimeoutSeconds == 0 {
			cfg.Profiles[i].TCP.TimeoutSeconds = 2 // Default to 2 seconds
		}
	}
}

// validateConfig performs semantic validation on the loaded configuration.
func validateConfig(cfg *datamodel.Config) error {
	// Check for empty configurations
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("no targets defined in configuration")
	}
	if len(cfg.Profiles) == 0 {
		return fmt.Errorf("no profiles defined in configuration")
	}

	// Build maps for quick lookup and duplicate checking
	profileNames, err := validateProfiles(cfg.Profiles)
	if err != nil {
		return err
	}

	snmpConfigNames, err := validateSNMPConfigs(cfg.SNMPConfigs)
	if err != nil {
		return err
	}

	err = validateTargets(cfg.Targets, profileNames)
	if err != nil {
		return err
	}

	// Validate profile references and details
	err = validateProfileDetails(cfg.Profiles, snmpConfigNames)
	if err != nil {
		return err
	}

	// Validate GlobalScanSettings DNS servers if provided
	err = validateGlobalDNSServers(cfg.GlobalScanSettings.DefaultDNSServers)
	if err != nil {
		return err
	}

	return nil
}

// validateProfiles validates the profile configurations and returns a map of valid profile names
func validateProfiles(profiles []datamodel.ProfileConfig) (map[string]bool, error) {
	profileNames := make(map[string]bool)
	for _, p := range profiles {
		if _, exists := profileNames[p.Name]; exists {
			return nil, fmt.Errorf("duplicate profile name found: %s", p.Name)
		}
		profileNames[p.Name] = true

		// Check TCP profile if enabled
		if p.TCP.IsEnabled && len(p.TCP.Ports) == 0 {
			return nil, fmt.Errorf("TCP profile for '%s' is enabled but has no ports specified", p.Name)
		}
	}
	return profileNames, nil
}

// validateSNMPConfigs validates SNMP configurations and returns a map of valid SNMP config names
func validateSNMPConfigs(snmpConfigs []datamodel.SNMPConfig) (map[string]bool, error) {
	snmpConfigNames := make(map[string]bool)
	for _, sc := range snmpConfigs {
		if _, exists := snmpConfigNames[sc.Name]; exists {
			return nil, fmt.Errorf("duplicate SNMP config name found: %s", sc.Name)
		}
		snmpConfigNames[sc.Name] = true

		if err := validateSNMPVersion(sc); err != nil {
			return nil, err
		}
	}
	return snmpConfigNames, nil
}

// validateSNMPVersion validates the SNMP version and required fields
func validateSNMPVersion(sc datamodel.SNMPConfig) error {
	// Validate SNMP version
	validVersions := map[string]bool{"v1": true, "v2c": true, "v3": true}
	if !validVersions[sc.Version] {
		return fmt.Errorf("invalid SNMP version '%s' for SNMP config '%s'", sc.Version, sc.Name)
	}

	// Further SNMPv3 validation
	if sc.Version == "v3" {
		return validateSNMPv3Config(sc)
	}
	return nil
}

// validateSNMPv3Config validates the SNMPv3 specific configuration
func validateSNMPv3Config(sc datamodel.SNMPConfig) error {
	if sc.SecurityLevel == "" {
		return fmt.Errorf("SNMPv3 config '%s' missing security_level", sc.Name)
	}
	if sc.Username == "" {
		return fmt.Errorf("SNMPv3 config '%s' missing username", sc.Name)
	}

	if sc.SecurityLevel == "authNoPriv" || sc.SecurityLevel == "authPriv" {
		if sc.AuthProtocol == "" || sc.AuthPassword == "" {
			return fmt.Errorf("SNMPv3 config '%s' with security '%s' requires auth_protocol and auth_password",
				sc.Name, sc.SecurityLevel)
		}
	}

	if sc.SecurityLevel == "authPriv" {
		if sc.PrivProtocol == "" || sc.PrivPassword == "" {
			return fmt.Errorf("SNMPv3 config '%s' with security 'authPriv' requires priv_protocol and priv_password", sc.Name)
		}
	}

	return nil
}

// validateTargets validates the target configurations
func validateTargets(targets []datamodel.TargetConfig, profileNames map[string]bool) error {
	targetNames := make(map[string]bool)
	for _, t := range targets {
		if _, exists := targetNames[t.Name]; exists {
			return fmt.Errorf("duplicate target name found: %s", t.Name)
		}
		targetNames[t.Name] = true

		if t.ProfileName == "" {
			return fmt.Errorf("target '%s' is missing a profile_name", t.Name)
		}
		if !profileNames[t.ProfileName] {
			return fmt.Errorf("target '%s' references non-existent profile '%s'", t.Name, t.ProfileName)
		}
		if len(t.Addresses) == 0 {
			return fmt.Errorf("target '%s' has no addresses defined", t.Name)
		}

		for _, addr := range t.Addresses {
			if addr == "" {
				return fmt.Errorf("target '%s' has an empty address string", t.Name)
			}
		}
	}
	return nil
}

// validateProfileDetails validates the detailed settings of each profile
func validateProfileDetails(profiles []datamodel.ProfileConfig, snmpConfigNames map[string]bool) error {
	for _, p := range profiles {
		if err := validateICMPSettings(p); err != nil {
			return err
		}

		if err := validateSNMPSettings(p, snmpConfigNames); err != nil {
			return err
		}

		if err := validateDNSSettings(p); err != nil {
			return err
		}

		if err := validateTCPSettings(p); err != nil {
			return err
		}
	}
	return nil
}

// validateICMPSettings validates the ICMP settings of a profile
func validateICMPSettings(p datamodel.ProfileConfig) error {
	if p.ICMP.IsEnabled {
		if p.ICMP.TimeoutSeconds <= 0 {
			return fmt.Errorf("ICMP profile for '%s' has invalid timeout: %d", p.Name, p.ICMP.TimeoutSeconds)
		}
		if p.ICMP.Retries < 0 {
			return fmt.Errorf("ICMP profile for '%s' has invalid retries: %d", p.Name, p.ICMP.Retries)
		}
	}
	return nil
}

// validateSNMPSettings validates the SNMP settings of a profile
func validateSNMPSettings(p datamodel.ProfileConfig, snmpConfigNames map[string]bool) error {
	if p.SNMP.IsEnabled {
		if len(p.SNMP.ConfigNamesOrdered) == 0 {
			return fmt.Errorf("SNMP profile for '%s' is enabled but has no config_names_ordered", p.Name)
		}
		for _, snmpConfName := range p.SNMP.ConfigNamesOrdered {
			if !snmpConfigNames[snmpConfName] {
				return fmt.Errorf("SNMP profile for '%s' references non-existent SNMP config '%s'", p.Name, snmpConfName)
			}
		}
	}
	return nil
}

// validateDNSSettings validates the DNS settings of a profile
func validateDNSSettings(p datamodel.ProfileConfig) error {
	if p.DNS.IsEnabled {
		if p.DNS.TimeoutSeconds <= 0 {
			return fmt.Errorf("DNS profile for '%s' has invalid timeout: %d", p.Name, p.DNS.TimeoutSeconds)
		}
		for _, server := range p.DNS.DNSServers {
			if err := validateDNSServer(server, p.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateTCPSettings validates the TCP settings of a profile
func validateTCPSettings(p datamodel.ProfileConfig) error {
	if p.TCP.IsEnabled {
		if p.TCP.TimeoutSeconds <= 0 {
			return fmt.Errorf("TCP profile for '%s' has invalid timeout: %d", p.Name, p.TCP.TimeoutSeconds)
		}
		if len(p.TCP.Ports) == 0 {
			return fmt.Errorf("TCP profile for '%s' is enabled but has no ports specified", p.Name)
		}
		for _, port := range p.TCP.Ports {
			if port <= 0 || port > 65535 {
				return fmt.Errorf("TCP profile for '%s' has invalid port number: %d", p.Name, port)
			}
		}
	}
	return nil
}

// validateDNSServer validates a single DNS server string
func validateDNSServer(server, profileName string) error {
	if server == "" {
		return fmt.Errorf("DNS profile for '%s' has an invalid DNS server entry: '%s'", profileName, server)
	}

	// Basic validation for DNS server format
	if !strings.Contains(server, ":") {
		return fmt.Errorf("DNS server '%s' in profile '%s' must include port (e.g., '8.8.8.8:53')", server, profileName)
	}
	return nil
}

// validateGlobalDNSServers validates the global DNS server settings
func validateGlobalDNSServers(servers []string) error {
	for _, server := range servers {
		if server == "" {
			return fmt.Errorf("global_scan_settings has an invalid default DNS server entry")
		}

		// Basic validation for DNS server format
		if !strings.Contains(server, ":") {
			return fmt.Errorf("DNS server '%s' in global_scan_settings must include port (e.g., '8.8.8.8:53')", server)
		}
	}
	return nil
}
