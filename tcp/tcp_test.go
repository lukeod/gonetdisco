package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
)

// setupTestListener sets up a TCP listener on a random port for testing
func setupTestListener(t *testing.T) (int, func()) {
	t.Helper()

	// Listen on a random port (port 0)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to set up test listener: %v", err)
	}

	// Get the port that was assigned
	port := listener.Addr().(*net.TCPAddr).Port

	// Set up a goroutine to accept connections
	done := make(chan struct{})
	go func() {
		defer listener.Close()
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					// Listener closed, just return
					return
				}
				// Close connection immediately
				conn.Close()
			}
		}
	}()

	// Return the port and a cleanup function
	return port, func() {
		close(done)
		listener.Close()
	}
}

func TestScanTCP(t *testing.T) {
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping TCP tests in short mode")
	}

	// Test scanning a specific port
	t.Run("Scan open port", func(t *testing.T) {
		// Set up a test listener
		port, cleanup := setupTestListener(t)
		defer cleanup()

		config := &datamodel.TCPConfig{
			Enabled: true,
			Timeout: 2,
			Ports:   []int{port},
		}

		ctx := context.Background()
		result, err := ScanTCP(ctx, "127.0.0.1", config)

		if err != nil {
			t.Fatalf("ScanTCP returned error: %v", err)
		}

		if !result.Reachable {
			t.Errorf("Expected 127.0.0.1:%d to be reachable", port)
		}

		if _, exists := result.OpenPorts[port]; !exists {
			t.Errorf("Expected port %d to be in OpenPorts map", port)
		}

		if result.ResponseTime <= 0 {
			t.Errorf("Expected ResponseTime > 0, got %v", result.ResponseTime)
		}
	})

	// Test scanning a closed port
	t.Run("Scan closed port", func(t *testing.T) {
		// Find a port that's likely to be closed
		// We'll use a high port in the ephemeral range
		unusedPort := 49151

		config := &datamodel.TCPConfig{
			Enabled: true,
			Timeout: 1, // Short timeout
			Ports:   []int{unusedPort},
		}

		ctx := context.Background()
		result, err := ScanTCP(ctx, "127.0.0.1", config)

		if err != nil {
			t.Fatalf("ScanTCP returned error: %v", err)
		}

		if result.Reachable {
			t.Errorf("Expected 127.0.0.1:%d to be unreachable", unusedPort)
		}

		if len(result.OpenPorts) > 0 {
			t.Errorf("Expected no open ports, got %v", result.OpenPorts)
		}
	})

	// Test scanning multiple ports (one open, one closed)
	t.Run("Scan multiple ports", func(t *testing.T) {
		// Set up a test listener
		port, cleanup := setupTestListener(t)
		defer cleanup()

		// Also scan an unused port
		unusedPort := 49152

		config := &datamodel.TCPConfig{
			Enabled: true,
			Timeout: 2,
			Ports:   []int{port, unusedPort},
		}

		ctx := context.Background()
		result, err := ScanTCP(ctx, "127.0.0.1", config)

		if err != nil {
			t.Fatalf("ScanTCP returned error: %v", err)
		}

		if !result.Reachable {
			t.Errorf("Expected 127.0.0.1 to be reachable (at least one open port)")
		}

		if _, exists := result.OpenPorts[port]; !exists {
			t.Errorf("Expected port %d to be in OpenPorts map", port)
		}

		if _, exists := result.OpenPorts[unusedPort]; exists {
			t.Errorf("Expected port %d to NOT be in OpenPorts map", unusedPort)
		}
	})

	// Test scanning with timeout
	t.Run("Scan with timeout", func(t *testing.T) {
		// Use a non-routable address to force timeout
		// RFC 5737 TEST-NET-1 address
		unreachableIP := "192.0.2.1"

		config := &datamodel.TCPConfig{
			Enabled: true,
			Timeout: 1, // Short timeout
			Ports:   []int{80, 443},
		}

		ctx := context.Background()
		startTime := time.Now()
		result, _ := ScanTCP(ctx, unreachableIP, config)
		duration := time.Since(startTime)

		// Check that we respect the timeout (with small buffer)
		maxExpectedDuration := time.Duration(config.Timeout)*time.Second + 500*time.Millisecond
		if duration > maxExpectedDuration {
			t.Errorf("Scan took longer than timeout: %v > %v", duration, maxExpectedDuration)
		}

		if result.Reachable {
			t.Errorf("Expected %s to be unreachable", unreachableIP)
		}

		if len(result.OpenPorts) > 0 {
			t.Errorf("Expected no open ports for unreachable IP, got %v", result.OpenPorts)
		}
	})

	// Test scanning with disabled config
	t.Run("Scan with disabled config", func(t *testing.T) {
		config := &datamodel.TCPConfig{
			Enabled: false,
			Timeout: 1,
			Ports:   []int{80, 443},
		}

		ctx := context.Background()
		result, err := ScanTCP(ctx, "127.0.0.1", config)

		if err != nil {
			t.Fatalf("ScanTCP returned error: %v", err)
		}

		if result.Reachable {
			t.Errorf("Expected disabled scan to return unreachable result")
		}

		if len(result.OpenPorts) > 0 {
			t.Errorf("Expected disabled scan to return no open ports, got %v", result.OpenPorts)
		}
	})

	// Test scanning with no ports
	t.Run("Scan with no ports", func(t *testing.T) {
		config := &datamodel.TCPConfig{
			Enabled: true,
			Timeout: 1,
			Ports:   []int{}, // Empty ports list
		}

		ctx := context.Background()
		result, err := ScanTCP(ctx, "127.0.0.1", config)

		if err != nil {
			t.Fatalf("ScanTCP returned error: %v", err)
		}

		if result.Reachable {
			t.Errorf("Expected scan with no ports to return unreachable result")
		}

		if len(result.OpenPorts) > 0 {
			t.Errorf("Expected scan with no ports to return no open ports, got %v", result.OpenPorts)
		}
	})
}

func TestGetServiceName(t *testing.T) {
	testCases := []struct {
		port     int
		expected string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{8080, "HTTP-Proxy"},
		{12345, "unknown"}, // Not in common ports map
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			service := getServiceName(tc.port)
			if service != tc.expected {
				t.Errorf("Expected port %d to return service '%s', got '%s'", tc.port, tc.expected, service)
			}
		})
	}
}
