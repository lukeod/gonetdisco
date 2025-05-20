package icmp

import (
	"testing"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/testutils"
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

	// Initialize the logger before running tests
	testutils.InitLogging()

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

	// Test 5: Invalid IP Address Format
	t.Run("Invalid IP Address Format", func(t *testing.T) {
		profile := datamodel.ICMPProfile{
			TimeoutSeconds: 1,
			Retries:        1,
		}
		_, err := PerformPing("this-is-not-an-ip", profile)
		if err == nil {
			t.Errorf("Expected error for invalid IP address format, got nil")
		}
		// We could also check for a specific error message if desired,
		// e.g., strings.Contains(err.Error(), "failed to create pinger")
	})

	// Test 6: Default Timeout Calculation (Profile Retries)
	t.Run("Default Timeout Profile Retries", func(t *testing.T) {
		profile := datamodel.ICMPProfile{
			// TimeoutSeconds: 0 by default in struct literal, triggering default calculation
			Retries:    2, // pinger.Count will be 2
			Privileged: false,
		}
		// pinger.Interval defaults to 1s (from pro-bing library)
		// defaultPacketTimeout is 2s (from icmp.go)
		// expectedPingerTimeout = (count * interval) + defaultPacketTimeout
		expectedPingerTimeout := (time.Duration(profile.Retries) * time.Second) + (2 * time.Second) // Should be (2*1s) + 2s = 4s

		startTime := time.Now()
		// Use an address from TEST-NET-1 (RFC 5737), unlikely to respond, to ensure full timeout duration is tested
		result, err := PerformPing("192.0.2.1", profile)
		duration := time.Since(startTime)

		t.Logf("Default Timeout Profile Retries: Expected pinger.Timeout ~%v. Actual duration %v. Error: %v. Result: %+v",
			expectedPingerTimeout, duration, err, result)

		// Check that the operation did not significantly exceed the calculated pinger.Timeout
		// Allow a buffer for overhead (e.g., 1 second)
		maxExpectedDuration := expectedPingerTimeout + 1000*time.Millisecond
		if duration > maxExpectedDuration {
			t.Errorf("Ping duration %v exceeded expected max duration %v (calculated pinger.Timeout %v + buffer)",
				duration, maxExpectedDuration, expectedPingerTimeout)
		}

		// Verify the outcome for an unpingable address
		if result == nil {
			t.Fatalf("Result should not be nil even on error/timeout")
		}
		if result.IsReachable {
			t.Errorf("Expected IsReachable=false for 192.0.2.1, got true. Result: %+v", result)
		}
		// err might be non-nil if pinger.Run() itself returns a timeout-related error
		if err != nil {
			t.Logf("PerformPing returned error: %v. This can be normal for a timeout on an unroutable address.", err)
		}
	})

	// Test 7: Default Timeout Calculation (Default Retries)
	t.Run("Default Timeout Default Retries", func(t *testing.T) {
		profile := datamodel.ICMPProfile{
			// TimeoutSeconds: 0 by default
			// Retries: 0 by default, so pinger.Count becomes 3 in PerformPing
			Privileged: false,
		}
		defaultPingerCount := 3 // As per PerformPing logic when profile.Retries is 0
		// expectedPingerTimeout = (count * interval) + defaultPacketTimeout
		expectedPingerTimeout := (time.Duration(defaultPingerCount) * time.Second) + (2 * time.Second) // Should be (3*1s) + 2s = 5s

		startTime := time.Now()
		result, err := PerformPing("192.0.2.1", profile)
		duration := time.Since(startTime)

		t.Logf("Default Timeout Default Retries: Expected pinger.Timeout ~%v. Actual duration %v. Error: %v. Result: %+v",
			expectedPingerTimeout, duration, err, result)

		maxExpectedDuration := expectedPingerTimeout + 1000*time.Millisecond
		if duration > maxExpectedDuration {
			t.Errorf("Ping duration %v exceeded expected max duration %v (calculated pinger.Timeout %v + buffer)",
				duration, maxExpectedDuration, expectedPingerTimeout)
		}

		if result == nil {
			t.Fatalf("Result should not be nil even on error/timeout")
		}
		if result.IsReachable {
			t.Errorf("Expected IsReachable=false for 192.0.2.1, got true. Result: %+v", result)
		}
		if err != nil {
			t.Logf("PerformPing returned error: %v. This can be normal for a timeout on an unroutable address.", err)
		}
	})

	// Test 8: Pinger Run Error with Zero Packets Sent Initially (e.g., privilege issue)
	t.Run("Pinger Run Error Initial", func(t *testing.T) {
		// This test aims to trigger the pingerError != nil && result.PacketsSent == 0 path
		// in PerformPing. This can happen if pinger.Run() fails due to a setup issue
		// (e.g., permissions for privileged ping) before OnFinish can report packets sent.
		profile := datamodel.ICMPProfile{
			Retries:         1,     // pinger.Count will be 1
			TimeoutSeconds:  1,     // Short timeout for the operation
			Privileged:      false, // Use unprivileged ping to ensure permission error
			PacketSizeBytes: 56,
		}
		expectedPacketsSent := profile.Retries // pinger.Count will be set to this

		// Use localhost, though the ping might not even start if listen fails
		result, err := PerformPing("127.0.0.1", profile)

		// We expect an error from PerformPing
		if err == nil {
			// If no error, it might mean the test environment allows unprivileged pings.
			// Let's skip this test since our environment successfully runs the ping.
			t.Skip("Skipping test because unprivileged ping to localhost succeeded, cannot test error path")
			return
		} else {
			t.Logf("Received expected error: %v", err)
		}

		if result == nil {
			t.Fatalf("Result should not be nil even on pinger.Run() error")
		}

		if result.IsReachable {
			t.Errorf("Expected IsReachable=false, got true. Result: %+v", result)
		}

		// This is the key check for the specific error handling path:
		// result.PacketsSent should be pinger.Count (which is profile.Retries)
		if result.PacketsSent != expectedPacketsSent {
			t.Errorf("Expected PacketsSent to be %d (pinger.Count), got %d. Result: %+v",
				expectedPacketsSent, result.PacketsSent, result)
		}

		if result.PacketsReceived != 0 {
			t.Errorf("Expected PacketsReceived=0, got %d. Result: %+v", result.PacketsReceived, result)
		}

		if result.PacketLossPercent != 100.0 {
			t.Errorf("Expected PacketLossPercent=100.0, got %f. Result: %+v", result.PacketLossPercent, result)
		}
	})
}
