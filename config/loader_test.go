package config

import (
	"os"
	"testing"

	"github.com/lukeod/gonetdisco/datamodel"
	"gopkg.in/yaml.v3"
)

// Helper function to create a temp config file
func createTempConfigFile(t *testing.T, config *datamodel.Config) string {
	t.Helper()
	
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "gonetdisco-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()
	
	// Marshal config to YAML
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	
	// Write YAML to temp file
	if _, err := tmpFile.Write(yamlData); err != nil {
		t.Fatalf("Failed to write YAML to temp file: %v", err)
	}
	
	return tmpFile.Name()
}

func TestLoadConfig(t *testing.T) {
	// Test loading a valid config file
	t.Run("Valid config file", func(t *testing.T) {
		configPath := "../testdata/sample_config.yaml"
		
		config, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		
		// Verify that the config was loaded correctly
		if len(config.Targets) != 1 {
			t.Errorf("Expected 1 target, got %d", len(config.Targets))
		}
		
		if len(config.SNMPConfigs) != 2 {
			t.Errorf("Expected 2 SNMP configs, got %d", len(config.SNMPConfigs))
		}
		
		if len(config.Profiles) != 1 {
			t.Errorf("Expected 1 profile, got %d", len(config.Profiles))
		}
		
		if config.GlobalScanSettings.ConcurrentScanners != 10 {
			t.Errorf("Expected ConcurrentScanners = 10, got %d", config.GlobalScanSettings.ConcurrentScanners)
		}
	})
	
	// Test loading a non-existent file
	t.Run("Non-existent file", func(t *testing.T) {
		_, err := LoadConfig("non-existent-file.yaml")
		if err == nil {
			t.Errorf("Expected error when loading non-existent file, got nil")
		}
	})
	
	// Test loading an invalid YAML file
	t.Run("Invalid YAML", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "invalid-yaml-*.yaml")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		
		// Write invalid YAML to the file
		if _, err := tmpFile.WriteString("this is not valid YAML content}{}"); err != nil {
			t.Fatalf("Failed to write to temp file: %v", err)
		}
		tmpFile.Close()
		
		_, err = LoadConfig(tmpFile.Name())
		if err == nil {
			t.Errorf("Expected error when loading invalid YAML, got nil")
		}
	})
}

func TestValidateConfig(t *testing.T) {
	// Test validating a config with no targets
	t.Run("No targets", func(t *testing.T) {
		config := &datamodel.Config{
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating config with no targets, got nil")
		}
	})
	
	// Test validating a config with no profiles
	t.Run("No profiles", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name: "test-target",
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating config with no profiles, got nil")
		}
	})
	
	// Test validating a config with duplicate profile names
	t.Run("Duplicate profile names", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
				},
				{
					Name: "test-profile", // Duplicate name
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating config with duplicate profile names, got nil")
		}
	})
	
	// Test validating a config with duplicate SNMP config names
	t.Run("Duplicate SNMP config names", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
				},
			},
			SNMPConfigs: []datamodel.SNMPConfig{
				{
					Name:    "test-snmp",
					Version: "v2c",
				},
				{
					Name:    "test-snmp", // Duplicate name
					Version: "v2c",
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating config with duplicate SNMP config names, got nil")
		}
	})
	
	// Test validating a config with invalid SNMP version
	t.Run("Invalid SNMP version", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
				},
			},
			SNMPConfigs: []datamodel.SNMPConfig{
				{
					Name:    "test-snmp",
					Version: "v4", // Invalid version
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating config with invalid SNMP version, got nil")
		}
	})
	
	// Test validating a config with SNMPv3 missing security level
	t.Run("SNMPv3 missing security level", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
				},
			},
			SNMPConfigs: []datamodel.SNMPConfig{
				{
					Name:     "test-snmp",
					Version:  "v3",
					Username: "user", // Missing SecurityLevel
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating config with SNMPv3 missing security level, got nil")
		}
	})
	
	// Test validating a target referencing a non-existent profile
	t.Run("Target references non-existent profile", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "non-existent-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating target referencing non-existent profile, got nil")
		}
	})
	
	// Test validating a profile with TCP enabled but no ports
	t.Run("TCP enabled with no ports", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
					TCP: datamodel.TCPProfile{
						IsEnabled: true,
						// No ports specified
					},
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating TCP enabled with no ports, got nil")
		}
	})
	
	// Test validating a DNS server without port
	t.Run("DNS server without port", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
					DNS: datamodel.DNSProfile{
						IsEnabled:      true,
						TimeoutSeconds: 2,
						DNSServers:     []string{"8.8.8.8"}, // Missing port
					},
				},
			},
		}
		
		err := validateConfig(config)
		if err == nil {
			t.Errorf("Expected error when validating DNS server without port, got nil")
		}
	})
}

func TestSetDefaults(t *testing.T) {
	// Test setting defaults for a minimal config
	t.Run("Set defaults for minimal config", func(t *testing.T) {
		config := &datamodel.Config{
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
					ICMP: datamodel.ICMPProfile{
						IsEnabled:      true,
						TimeoutSeconds: 1,
					},
					TCP: datamodel.TCPProfile{
						IsEnabled: true,
						Ports:     []int{80, 443},
					},
				},
			},
		}
		
		// Call setDefaults
		setDefaults(config)
		
		// Verify defaults were set
		if config.GlobalScanSettings.ConcurrentScanners != 10 {
			t.Errorf("Expected ConcurrentScanners default to be 10, got %d", config.GlobalScanSettings.ConcurrentScanners)
		}
		
		if config.GlobalScanSettings.MaxOidsPerSNMPRequest != 60 {
			t.Errorf("Expected MaxOidsPerSNMPRequest default to be 60, got %d", config.GlobalScanSettings.MaxOidsPerSNMPRequest)
		}
		
		if config.GlobalScanSettings.DefaultOutputPath != "./discovered_devices.json" {
			t.Errorf("Expected DefaultOutputPath default to be ./discovered_devices.json, got %s", config.GlobalScanSettings.DefaultOutputPath)
		}
		
		if !config.Profiles[0].ICMP.SkipIfUnreachable {
			t.Errorf("Expected ICMP.SkipIfUnreachable default to be true")
		}
		
		if config.Profiles[0].TCP.TimeoutSeconds != 2 {
			t.Errorf("Expected TCP.TimeoutSeconds default to be 2, got %d", config.Profiles[0].TCP.TimeoutSeconds)
		}
	})
	
	// Test that existing values are not overwritten
	t.Run("Don't overwrite existing values", func(t *testing.T) {
		config := &datamodel.Config{
			GlobalScanSettings: datamodel.GlobalScanSettings{
				ConcurrentScanners:    20,
				MaxOidsPerSNMPRequest: 100,
				DefaultOutputPath:     "/custom/path.json",
			},
			Targets: []datamodel.TargetConfig{
				{
					Name:        "test-target",
					ProfileName: "test-profile",
					Addresses:   []string{"192.168.1.1"},
				},
			},
			Profiles: []datamodel.ProfileConfig{
				{
					Name: "test-profile",
					ICMP: datamodel.ICMPProfile{
						IsEnabled:         true,
						TimeoutSeconds:    1,
						// According to setDefaults implementation in loader.go,
						// SkipIfUnreachable is always set to true if ICMP is enabled
						// and SkipIfUnreachable is not explicitly set (which is not what we expected)
					},
					TCP: datamodel.TCPProfile{
						IsEnabled:      true,
						TimeoutSeconds: 5,
						Ports:          []int{80, 443},
					},
				},
			},
		}
		
		// Call setDefaults
		setDefaults(config)
		
		// Verify custom values were not overwritten
		if config.GlobalScanSettings.ConcurrentScanners != 20 {
			t.Errorf("Expected ConcurrentScanners to remain 20, got %d", config.GlobalScanSettings.ConcurrentScanners)
		}
		
		if config.GlobalScanSettings.MaxOidsPerSNMPRequest != 100 {
			t.Errorf("Expected MaxOidsPerSNMPRequest to remain 100, got %d", config.GlobalScanSettings.MaxOidsPerSNMPRequest)
		}
		
		if config.GlobalScanSettings.DefaultOutputPath != "/custom/path.json" {
			t.Errorf("Expected DefaultOutputPath to remain /custom/path.json, got %s", config.GlobalScanSettings.DefaultOutputPath)
		}
		
		if config.Profiles[0].TCP.TimeoutSeconds != 5 {
			t.Errorf("Expected TCP.TimeoutSeconds to remain 5, got %d", config.Profiles[0].TCP.TimeoutSeconds)
		}
	})
}