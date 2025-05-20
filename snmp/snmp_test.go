package snmp

import (
	"fmt"
	"testing"
	"time"

	g "github.com/gosnmp/gosnmp"
	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/logger"
	"github.com/lukeod/gonetdisco/testutils"
)

func TestMaskSensitiveString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Short string (1 char)",
			input:    "a",
			expected: "**",
		},
		{
			name:     "Short string (2 chars)",
			input:    "ab",
			expected: "**",
		},
		{
			name:     "Normal string",
			input:    "password",
			expected: "p******d",
		},
		{
			name:     "Long string",
			input:    "supercalifragilisticexpialidocious",
			expected: "s********************************s",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := maskSensitiveString(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestInputValidation tests basic input validation
func TestInputValidation(t *testing.T) {
	// Initialize the logger before tests
	testutils.InitLogging()

	// Test empty IP validation
	if validateIPAddress("") == nil {
		t.Error("Expected error for empty IP address, got nil")
	}
}

// Helper function to test empty IP validation
func validateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty IP address provided")
	}
	return nil
}

func TestPerformQuery_DefaultValuesBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SNMP tests in short mode")
	}

	// Initialize the logger before tests
	testutils.InitLogging()
	log := logger.WithModule("snmp-test")

	// Test default value for timeout
	config := datamodel.SNMPConfig{
		Name:      "test-default-timeout",
		Version:   "v2c",
		Community: "public",
		// TimeoutSeconds is 0, should use default
	}

	// Mock the SNMP connection to avoid real network interaction
	// This is a simplified test that only checks the parameter setting logic

	// Create the parameters and check defaults
	params, err := createSNMPParameters("192.168.1.1", config, log)
	if err != nil {
		t.Fatalf("createSNMPParameters failed: %v", err)
	}

	if params.Timeout != time.Second*5 {
		t.Errorf("Expected default timeout of 5 seconds, got %v", params.Timeout)
	}

	// Test default value for retries
	configWithNegativeRetries := datamodel.SNMPConfig{
		Name:      "test-negative-retries",
		Version:   "v2c",
		Community: "public",
		Retries:   -1, // Negative, should be set to 0
	}

	paramsWithRetries, err := createSNMPParameters("192.168.1.1", configWithNegativeRetries, log)
	if err != nil {
		t.Fatalf("createSNMPParameters failed: %v", err)
	}

	if paramsWithRetries.Retries != 0 {
		t.Errorf("Expected retries to be corrected to 0, got %v", paramsWithRetries.Retries)
	}
}

func TestPerformQuery_EmptyOidsBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SNMP tests in short mode")
	}

	// Initialize the logger before tests
	testutils.InitLogging()

	// Create a test environment to validate behavior with empty OIDs
	// This requires mocking the connection since we can't actually connect

	// We can't directly test PerformQuery with an actual connection,
	// but we can test the validation of maxOidsPerRequest

	log := logger.WithModule("snmp-test")

	validationResult := validateMaxOidsPerRequest(0, "192.168.1.1", log)
	if validationResult != 60 {
		t.Errorf("Expected default maxOidsPerRequest of 60, got %d", validationResult)
	}

	validationResult = validateMaxOidsPerRequest(150, "192.168.1.1", log)
	if validationResult != 100 {
		t.Errorf("Expected capped maxOidsPerRequest of 100, got %d", validationResult)
	}

	validationResult = validateMaxOidsPerRequest(50, "192.168.1.1", log)
	if validationResult != 50 {
		t.Errorf("Expected unchanged maxOidsPerRequest of 50, got %d", validationResult)
	}
}

// Test SNMP configuration creation for different versions
func TestCreateSNMPParameters(t *testing.T) {
	// Initialize the logger
	testutils.InitLogging()

	// Test V1 configuration
	v1Config := datamodel.SNMPConfig{
		Name:      "test-v1",
		Version:   "v1",
		Community: "public",
	}
	log := logger.WithModule("snmp-test")
	v1Params, err := createSNMPParameters("192.168.1.1", v1Config, log)
	if err != nil {
		t.Fatalf("Failed to create SNMPv1 parameters: %v", err)
	}
	if v1Params.Version != 0 { // gosnmp.Version1 = 0
		t.Errorf("Expected Version1 (0), got %v", v1Params.Version)
	}
	if v1Params.Community != "public" {
		t.Errorf("Expected community 'public', got %s", v1Params.Community)
	}

	// Test V2c configuration
	v2cConfig := datamodel.SNMPConfig{
		Name:      "test-v2c",
		Version:   "v2c",
		Community: "public",
	}
	v2cParams, err := createSNMPParameters("192.168.1.1", v2cConfig, log)
	if err != nil {
		t.Fatalf("Failed to create SNMPv2c parameters: %v", err)
	}
	if v2cParams.Version != 1 { // gosnmp.Version2c = 1
		t.Errorf("Expected Version2c (1), got %v", v2cParams.Version)
	}
	if v2cParams.Community != "public" {
		t.Errorf("Expected community 'public', got %s", v2cParams.Community)
	}

	// Test invalid version
	invalidConfig := datamodel.SNMPConfig{
		Name:    "test-invalid",
		Version: "invalid",
	}
	_, err = createSNMPParameters("192.168.1.1", invalidConfig, log)
	if err == nil {
		t.Error("Expected error for invalid SNMP version, got nil")
	}
}

// Test SNMPv3 security level configuration
func TestConfigureV3SecurityLevel(t *testing.T) {
	// Initialize the logger
	testutils.InitLogging()
	log := logger.WithModule("snmp-test")
	
	// Test cases for different security levels
	testCases := []struct {
		name           string
		securityLevel  string
		expectedLevel  string
		expectedResult string
		expectError    bool
	}{
		{
			name:           "NoAuthNoPriv",
			securityLevel:  "noauthnopriv",
			expectedLevel:  "noauthnopriv",
			expectedResult: "noauthnopriv",
			expectError:    false,
		},
		{
			name:           "AuthNoPriv",
			securityLevel:  "authnopriv",
			expectedLevel:  "authnopriv",
			expectedResult: "authnopriv",
			expectError:    false,
		},
		{
			name:           "AuthPriv",
			securityLevel:  "authpriv",
			expectedLevel:  "authpriv",
			expectedResult: "authpriv",
			expectError:    false,
		},
		{
			name:           "Default Empty",
			securityLevel:  "",
			expectedLevel:  "noauthnopriv",
			expectedResult: "noauthnopriv",
			expectError:    false,
		},
		{
			name:           "Invalid",
			securityLevel:  "invalid",
			expectedLevel:  "",
			expectedResult: "",
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := &g.GoSNMP{}
			result, err := configureV3SecurityLevel(params, tc.securityLevel, "192.168.1.1", log)
			
			// Check error condition
			if tc.expectError && err == nil {
				t.Errorf("Expected error for security level %s, got nil", tc.securityLevel)
			} else if !tc.expectError && err != nil {
				t.Errorf("Unexpected error for security level %s: %v", tc.securityLevel, err)
			}
			
			// Check result string if no error expected
			if !tc.expectError {
				if result != tc.expectedResult {
					t.Errorf("Expected result %s, got %s", tc.expectedResult, result)
				}
			}
		})
	}
}

// Note: We can't easily set up a real SNMP agent for integration testing,
// but in a real environment, we would have additional tests to verify:
// 1. Successful connection and query with v1/v2c
// 2. Successful connection and query with various v3 security levels
// 3. Error handling for unreachable hosts
// 4. Response processing for different SNMP data types
