// Package testutils provides helper functions and utilities for testing the gonetdisco codebase.
package testutils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/logger"
	"gopkg.in/yaml.v3"
)

// LoadTestConfig loads test YAML configuration from a file.
func LoadTestConfig(t *testing.T, fileName string) *datamodel.Config {
	t.Helper()
	
	// Read the YAML file
	yamlFile, err := os.ReadFile(filepath.Join("testdata", fileName))
	if err != nil {
		t.Fatalf("Failed to read test config file %s: %v", fileName, err)
	}

	// Unmarshal YAML into Config struct
	var config datamodel.Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML from %s: %v", fileName, err)
	}

	return &config
}

// CreateTempConfigFile creates a temporary YAML configuration file from a Config struct.
func CreateTempConfigFile(t *testing.T, config *datamodel.Config) string {
	t.Helper()
	
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "gonetdisco-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Marshal the config to YAML
	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config to YAML: %v", err)
	}

	// Write the YAML to the temp file
	if _, err := tmpFile.Write(yamlBytes); err != nil {
		t.Fatalf("Failed to write config to temp file: %v", err)
	}

	return tmpFile.Name()
}

// CreateTestDevice creates a DiscoveredDevice with basic fields filled in for testing.
func CreateTestDevice(ipAddress string) *datamodel.DiscoveredDevice {
	return &datamodel.DiscoveredDevice{
		IPAddress:   ipAddress,
		TargetName:  "test-target",
		ProfileName: "test-profile",
		Timestamp:   "2023-01-01T00:00:00Z",
	}
}

// SaveTestDevicesToJSON saves a slice of DiscoveredDevice to a JSON file.
func SaveTestDevicesToJSON(t *testing.T, devices []*datamodel.DiscoveredDevice, filePath string) {
	t.Helper()
	
	// Create the directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory %s: %v", dir, err)
	}

	// Marshal the devices to JSON
	jsonBytes, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal devices to JSON: %v", err)
	}

	// Write the JSON to the file
	if err := os.WriteFile(filePath, jsonBytes, 0644); err != nil {
		t.Fatalf("Failed to write JSON to file %s: %v", filePath, err)
	}
}

// CompareDevices compares two DiscoveredDevice structs and fails the test if they differ.
func CompareDevices(t *testing.T, expected, actual *datamodel.DiscoveredDevice) {
	t.Helper()

	// Convert to JSON for comparison
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Failed to marshal expected device: %v", err)
	}

	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("Failed to marshal actual device: %v", err)
	}

	// Compare JSON strings
	if string(expectedJSON) != string(actualJSON) {
		t.Errorf("Devices differ:\nExpected: %s\nActual: %s", expectedJSON, actualJSON)
	}
}

// InitLogging ensures the logger is properly initialized for tests
// This helps prevent nil pointer dereference errors in tests that use logging
func InitLogging() {
	logger.Init(logger.LevelDebug)
}