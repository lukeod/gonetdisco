package output

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/testutils"
)

// TestNewOutputManager verifies that the output manager is created correctly
func TestNewOutputManager(t *testing.T) {
	// Initialize logging
	testutils.InitLogging()

	// Create a test results channel
	resultsChan := make(chan datamodel.DiscoveredDevice)
	outputPath := "test_output.json"
	totalIPs := 100

	// Create a new output manager
	om := NewOutputManager(resultsChan, outputPath, totalIPs)

	// Verify the fields were initialized correctly
	if om.ResultsChannel != resultsChan {
		t.Error("ResultsChannel not set correctly")
	}
	if om.ConfiguredOutputPath != outputPath {
		t.Error("OutputPath not set correctly")
	}
	if om.TotalIPsToScan != totalIPs {
		t.Error("TotalIPsToScan not set correctly")
	}
	if om.MaxLastNDevices != 5 {
		t.Error("MaxLastNDevices not set to default value")
	}
	if om.UIUpdateInterval != time.Second {
		t.Error("UIUpdateInterval not set to default value")
	}
	if om.doneChan == nil {
		t.Error("doneChan not initialized")
	}
	if len(om.AllDiscoveredDevices) != 0 {
		t.Error("AllDiscoveredDevices not initialized to empty slice")
	}
}

// TestRenderProgressBar verifies that the progress bar is rendered correctly
func TestRenderProgressBar(t *testing.T) {
	// Initialize logging
	testutils.InitLogging()

	// Create a test output manager
	om := &OutputManager{}

	// Test cases with different percentages
	testCases := []struct {
		percentage float64
		expected   int // Number of = characters expected
	}{
		{0, 0},
		{25, 12}, // 25% of 50 characters = 12.5, so 12
		{50, 25},
		{75, 37}, // 75% of 50 characters = 37.5, so 37
		{100, 50},
	}

	for _, tc := range testCases {
		t.Run("percentage_"+string(rune(int(tc.percentage))), func(t *testing.T) {
			bar := om.renderProgressBar(tc.percentage)

			// Count = characters
			eqCount := 0
			for _, c := range bar {
				if c == '=' {
					eqCount++
				}
			}

			if eqCount != tc.expected {
				t.Errorf("For %.2f%%, expected %d = characters, got %d", tc.percentage, tc.expected, eqCount)
			}

			// Check total length
			if len(bar) != 50 {
				t.Errorf("Expected bar length of 50, got %d", len(bar))
			}
		})
	}
}

// TestTruncateString verifies that strings are truncated correctly
func TestTruncateString(t *testing.T) {
	// Initialize logging
	testutils.InitLogging()

	// Create a test output manager
	om := &OutputManager{}

	// Test cases with different string lengths
	testCases := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"empty_string", "", 10, ""},
		{"short_string", "test", 10, "test"},
		{"equal_length", "1234567890", 10, "1234567890"},
		{"truncate_with_ellipsis", "This is a long string", 10, "This is..."},
		{"truncate_too_short_for_ellipsis", "123456789", 3, "123"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := om.truncateString(tc.input, tc.maxLen)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestWriteJSONOutput verifies that the JSON output is written correctly
func TestWriteJSONOutput(t *testing.T) {
	// Initialize logging
	testutils.InitLogging()

	// Create a temporary file for testing
	tmpfile, err := os.CreateTemp("", "test_output_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	// Create a test output manager
	om := &OutputManager{
		ConfiguredOutputPath: tmpfile.Name(),
		AllDiscoveredDevices: []datamodel.DiscoveredDevice{
			{
				IPAddress: "192.168.1.1",
				DNSResult: &datamodel.DNSScanResult{
					PTRRecords: []string{"test.example.com"},
				},
			},
			{
				IPAddress: "192.168.1.2",
				DNSResult: &datamodel.DNSScanResult{
					PTRRecords: []string{"test2.example.com"},
				},
			},
		},
	}

	// Write the JSON output
	om.WriteJSONOutput()

	// Read the file back and verify
	data, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Parse the JSON
	var devices []datamodel.DiscoveredDevice
	err = json.Unmarshal(data, &devices)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the devices were saved correctly
	if len(devices) != 2 {
		t.Fatalf("Expected 2 devices, got %d", len(devices))
	}

	// Check first device
	if devices[0].IPAddress != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", devices[0].IPAddress)
	}
	if devices[0].DNSResult == nil || len(devices[0].DNSResult.PTRRecords) != 1 || devices[0].DNSResult.PTRRecords[0] != "test.example.com" {
		t.Error("First device DNS record not saved correctly")
	}

	// Check second device
	if devices[1].IPAddress != "192.168.1.2" {
		t.Errorf("Expected IP 192.168.1.2, got %s", devices[1].IPAddress)
	}
	if devices[1].DNSResult == nil || len(devices[1].DNSResult.PTRRecords) != 1 || devices[1].DNSResult.PTRRecords[0] != "test2.example.com" {
		t.Error("Second device DNS record not saved correctly")
	}
}

// TestWriteJSONOutput_EmptyDevices verifies handling of empty device lists
func TestWriteJSONOutput_EmptyDevices(t *testing.T) {
	// Initialize logging
	testutils.InitLogging()

	// Create a temporary file for testing
	tmpfile, err := os.CreateTemp("", "test_output_empty_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	// Create a test output manager with no devices
	om := &OutputManager{
		ConfiguredOutputPath: tmpfile.Name(),
		AllDiscoveredDevices: []datamodel.DiscoveredDevice{},
	}

	// Write the JSON output
	om.WriteJSONOutput()

	// Read the file back and verify
	data, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Parse the JSON
	var devices []datamodel.DiscoveredDevice
	err = json.Unmarshal(data, &devices)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the empty array was saved correctly
	if len(devices) != 0 {
		t.Fatalf("Expected 0 devices, got %d", len(devices))
	}
}
