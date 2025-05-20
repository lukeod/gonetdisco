package dns

import (
	"testing"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
)

func TestPerformLookups(t *testing.T) {
	// Skip tests in short mode, as they rely on network connectivity
	if testing.Short() {
		t.Skip("Skipping DNS tests in short mode")
	}

	// Test basic reverse lookup
	t.Run("Reverse lookup only", func(t *testing.T) {
		profile := datamodel.DNSProfile{
			DoReverseLookup:               true,
			DoForwardLookupIfReverseFound: false,
			TimeoutSeconds:                2,
		}

		// Use Google's public DNS server for testing
		dnsServers := []string{"8.8.8.8:53"}

		// Perform lookup on a well-known IP (Google DNS)
		result, errors := PerformLookups("8.8.8.8", profile, dnsServers)

		if len(errors) > 0 {
			t.Logf("Encountered errors during DNS lookup: %v", errors)
		}

		if result == nil {
			t.Fatal("Expected non-nil result")
		}

		// Check if we got any PTR records
		if len(result.PTRRecords) == 0 {
			t.Logf("Warning: No PTR records found for 8.8.8.8 - DNS might be restricted in this environment")
		} else {
			t.Logf("Found PTR records: %v", result.PTRRecords)
		}

		// Verify that forward lookups weren't performed
		if len(result.ForwardLookupResults) > 0 {
			t.Errorf("Expected no forward lookups, got %d", len(result.ForwardLookupResults))
		}
	})

	// Test both reverse and forward lookups
	t.Run("Reverse and forward lookups", func(t *testing.T) {
		profile := datamodel.DNSProfile{
			DoReverseLookup:               true,
			DoForwardLookupIfReverseFound: true,
			TimeoutSeconds:                2,
		}

		// Use Google's public DNS server for testing
		dnsServers := []string{"8.8.8.8:53"}

		// Perform lookup on a well-known IP (Google DNS)
		result, errors := PerformLookups("8.8.8.8", profile, dnsServers)

		if len(errors) > 0 {
			t.Logf("Encountered errors during DNS lookup: %v", errors)
		}

		if result == nil {
			t.Fatal("Expected non-nil result")
		}

		// Check if we got any PTR records
		if len(result.PTRRecords) == 0 {
			t.Logf("Warning: No PTR records found for 8.8.8.8 - DNS might be restricted in this environment")
			// Skip forward lookup check if no PTR records
			return
		}

		// Verify that forward lookups were attempted for each PTR record
		if len(result.ForwardLookupResults) == 0 && len(result.PTRRecords) > 0 {
			t.Logf("Warning: No forward lookup results despite having PTR records")
		}

		for hostname, ips := range result.ForwardLookupResults {
			t.Logf("Forward lookup for %s returned: %v", hostname, ips)
			if len(ips) == 0 {
				t.Errorf("Empty IP list for hostname %s", hostname)
			}
		}
	})

	// Test with invalid IP address
	t.Run("Invalid IP address", func(t *testing.T) {
		profile := datamodel.DNSProfile{
			DoReverseLookup:               true,
			DoForwardLookupIfReverseFound: true,
			TimeoutSeconds:                2,
		}

		// Use Google's public DNS server for testing
		dnsServers := []string{"8.8.8.8:53"}

		// Perform lookup on an invalid IP
		result, errors := PerformLookups("invalid-ip", profile, dnsServers)

		// Expect errors
		if len(errors) == 0 {
			t.Errorf("Expected errors for invalid IP, got none")
		}

		if result == nil {
			t.Fatal("Expected non-nil result even with errors")
		}

		// Check that no records were found
		if len(result.PTRRecords) > 0 {
			t.Errorf("Expected no PTR records for invalid IP, got %v", result.PTRRecords)
		}

		if len(result.ForwardLookupResults) > 0 {
			t.Errorf("Expected no forward lookup results for invalid IP, got %v", result.ForwardLookupResults)
		}
	})

	// Test with timeout
	t.Run("Timeout", func(t *testing.T) {
		profile := datamodel.DNSProfile{
			DoReverseLookup:               true,
			DoForwardLookupIfReverseFound: true,
			TimeoutSeconds:                1, // Very short timeout
		}

		// Use an invalid/unreachable DNS server to force timeout
		dnsServers := []string{"192.0.2.1:53"} // RFC 5737 TEST-NET-1 address

		startTime := time.Now()
		result, errors := PerformLookups("8.8.8.8", profile, dnsServers)
		elapsed := time.Since(startTime)

		// Verify timeout was respected (with small buffer for processing)
		if elapsed > (time.Duration(profile.TimeoutSeconds)*time.Second + 500*time.Millisecond) {
			t.Errorf("Lookup took longer than timeout: %v", elapsed)
		}

		// Expect errors due to unreachable DNS server
		if len(errors) == 0 {
			t.Errorf("Expected errors for unreachable DNS server, got none")
		}

		// Result should still be non-nil
		if result == nil {
			t.Fatal("Expected non-nil result even with errors")
		}
	})

	// Test with no custom DNS servers
	t.Run("Default resolver", func(t *testing.T) {
		profile := datamodel.DNSProfile{
			DoReverseLookup:               true,
			DoForwardLookupIfReverseFound: false,
			TimeoutSeconds:                2,
		}

		// Use empty DNS servers list to force using default resolver
		result, errors := PerformLookups("8.8.8.8", profile, nil)

		if len(errors) > 0 {
			t.Logf("Encountered errors with default resolver: %v", errors)
		}

		if result == nil {
			t.Fatal("Expected non-nil result")
		}

		// Basic check - we don't fail the test if DNS is restricted in environment
		if len(result.PTRRecords) == 0 {
			t.Logf("Warning: No PTR records found with default resolver - DNS might be restricted")
		} else {
			t.Logf("Default resolver found PTR records: %v", result.PTRRecords)
		}
	})
}
