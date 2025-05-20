// Package config is responsible for loading the YAML configuration file,
// unmarshalling it into the structures defined in the datamodel module,
// and performing validation to ensure the configuration is semantically correct.
package config

import (
	"fmt"
	"os"
	"strings"

	"go-netdiscover/datamodel"
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
	profileNames := make(map[string]bool)
	for _, p := range cfg.Profiles {
		if _, exists := profileNames[p.Name]; exists {
			return fmt.Errorf("duplicate profile name found: %s", p.Name)
		}
		profileNames[p.Name] = true
	}

	snmpConfigNames := make(map[string]bool)
	for _, sc := range cfg.SNMPConfigs {
		if _, exists := snmpConfigNames[sc.Name]; exists {
			return fmt.Errorf("duplicate SNMP config name found: %s", sc.Name)
		}
		snmpConfigNames[sc.Name] = true

		// Validate SNMP version
		validVersions := map[string]bool{"v1": true, "v2c": true, "v3": true}
		if !validVersions[sc.Version] {
			return fmt.Errorf("invalid SNMP version '%s' for SNMP config '%s'", sc.Version, sc.Name)
		}

		// Further SNMPv3 validation
		if sc.Version == "v3" {
			if sc.SecurityLevel == "" {
				return fmt.Errorf("SNMPv3 config '%s' missing security_level", sc.Name)
			}
			if sc.Username == "" {
				return fmt.Errorf("SNMPv3 config '%s' missing username", sc.Name)
			}
			if sc.SecurityLevel == "authNoPriv" || sc.SecurityLevel == "authPriv" {
				if sc.AuthProtocol == "" || sc.AuthPassword == "" {
					return fmt.Errorf("SNMPv3 config '%s' with security '%s' requires auth_protocol and auth_password", sc.Name, sc.SecurityLevel)
				}
			}
			if sc.SecurityLevel == "authPriv" {
				if sc.PrivProtocol == "" || sc.PrivPassword == "" {
					return fmt.Errorf("SNMPv3 config '%s' with security 'authPriv' requires priv_protocol and priv_password", sc.Name)
				}
			}
		}
	}

	targetNames := make(map[string]bool)
	for _, t := range cfg.Targets {
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

	// Validate profiles
	for _, p := range cfg.Profiles {
		if p.ICMP.IsEnabled {
			if p.ICMP.TimeoutSeconds <= 0 {
				return fmt.Errorf("ICMP profile for '%s' has invalid timeout: %d", p.Name, p.ICMP.TimeoutSeconds)
			}
			if p.ICMP.Retries < 0 {
				return fmt.Errorf("ICMP profile for '%s' has invalid retries: %d", p.Name, p.ICMP.Retries)
			}
		}
		
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
		
		if p.DNS.IsEnabled {
			if p.DNS.TimeoutSeconds <= 0 {
				return fmt.Errorf("DNS profile for '%s' has invalid timeout: %d", p.Name, p.DNS.TimeoutSeconds)
			}
			for _, server := range p.DNS.DNSServers {
				if server == "" {
					return fmt.Errorf("DNS profile for '%s' has an invalid DNS server entry: '%s'", p.Name, server)
				}
				
				// Basic validation for DNS server format
				if !strings.Contains(server, ":") {
					return fmt.Errorf("DNS server '%s' in profile '%s' must include port (e.g., '8.8.8.8:53')", server, p.Name)
				}
			}
		}
	}
	
	// Validate GlobalScanSettings DNS servers if provided
	for _, server := range cfg.GlobalScanSettings.DefaultDNSServers {
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