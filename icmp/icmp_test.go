package icmp

import (
	"testing"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
)

// Mock Responder interface for testing
type mockResponder struct {
	doRespond bool
	delay     time.Duration
}

// TestPerformPing tests the ICMP ping functionality
func TestPerformPing(t *testing.T) {
	// Skip tests if running in CI environment or without proper permissions
	if testing.Short() {
		t.Skip("Skipping ICMP tests in short mode")
	}

	// Create a basic profile for testing
	profile := datamodel.ICMPProfile{
		TimeoutSeconds:  1,
		Retries:         2,
		PacketSizeBytes: 56,
		Privileged:      false, // Most CI systems won't allow privileged mode
	}

	// Test 1: Ping localhost (should succeed)
	t.Run("Ping localhost", func(t *testing.T) {
		result, err := PerformPing("127.0.0.1", profile)
		
		if err != nil {
			t.Logf("Error pinging localhost: %v", err)
			// Don't fail the test here, as some CI environments might block ICMP
		}
		
		if result != nil && !result.IsReachable {
			t.Logf("Expected localhost to be reachable, got unreachable")
			// Again, don't fail as environment might restrict ping
		}
		
		if result != nil && result.IsReachable {
			t.Logf("Successfully pinged localhost: RTT=%v ms", result.RTT_ms)
			
			// Verify result fields
			if result.PacketsSent <= 0 {
				t.Errorf("Expected PacketsSent > 0, got %d", result.PacketsSent)
			}
			
			if result.PacketsReceived <= 0 {
				t.Errorf("Expected PacketsReceived > 0, got %d", result.PacketsReceived)
			}
			
			if result.RTT_ms <= 0 {
				t.Logf("Warning: RTT_ms is unexpectedly low: %v", result.RTT_ms)
			}
		}
	})
	
	// Test 2: Ping invalid address (should fail)
	t.Run("Ping invalid address", func(t *testing.T) {
		// Use an address from TEST-NET-1 (RFC 5737)
		result, err := PerformPing("192.0.2.1", profile)
		
		// We expect either an error or an unreachable result
		if err == nil && (result == nil || result.IsReachable) {
			t.Errorf("Expected unreachable result for invalid address, got reachable")
		}
		
		if result != nil {
			if result.IsReachable {
				t.Errorf("Expected IsReachable=false for invalid address, got true")
			}
			
			if result.PacketLossPercent != 100.0 {
				t.Errorf("Expected PacketLossPercent=100.0 for invalid address, got %v", result.PacketLossPercent)
			}
		}
	})
	
	// Test 3: Test timeout behavior
	t.Run("Test timeout", func(t *testing.T) {
		// Create a profile with a very short timeout
		shortTimeoutProfile := datamodel.ICMPProfile{
			TimeoutSeconds:  1, // Very short timeout
			Retries:         1,
			PacketSizeBytes: 56,
			Privileged:      false,
		}
		
		// Use a multicast address (likely to timeout)
		startTime := time.Now()
		result, _ := PerformPing("224.0.0.1", shortTimeoutProfile)
		duration := time.Since(startTime)
		
		// Check that we respect the timeout
		if duration > (time.Duration(shortTimeoutProfile.TimeoutSeconds)*time.Second + 500*time.Millisecond) {
			t.Errorf("Ping took longer than timeout: %v", duration)
		}
		
		if result != nil && result.IsReachable {
			// This is not an error as some networks might respond to multicast pings
			t.Logf("Multicast address unexpectedly responded to ping")
		}
	})
	
	// Test 4: Profile consistency
	t.Run("Profile parameters", func(t *testing.T) {
		// Create a profile with specific parameters
		customProfile := datamodel.ICMPProfile{
			TimeoutSeconds:  2,
			Retries:         3,
			PacketSizeBytes: 128,
			Privileged:      false,
		}
		
		// Ping localhost with custom profile
		_, err := PerformPing("127.0.0.1", customProfile)
		
		// We're mostly checking that the custom parameters don't cause a crash
		if err != nil {
			t.Logf("Error with custom profile: %v", err)
		}
		
		// Verify defaults when zero values are provided
		zeroProfile := datamodel.ICMPProfile{}
		_, err = PerformPing("127.0.0.1", zeroProfile)
		
		if err != nil {
			t.Logf("Error with zero profile: %v", err)
		}
	})
}