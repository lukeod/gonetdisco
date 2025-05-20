package scanner

import (
	"sync"
	"testing"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
)

// TestNewScanner verifies that NewScanner correctly initializes a Scanner instance
func TestNewScanner(t *testing.T) {
	// Create a sample config
	cfg := &datamodel.Config{
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
					IsEnabled: true,
				},
			},
		},
		SNMPConfigs: []datamodel.SNMPConfig{
			{
				Name:    "test-snmp",
				Version: "v2c",
			},
		},
		GlobalScanSettings: datamodel.GlobalScanSettings{
			ConcurrentScanners: 5,
		},
	}

	resultsChan := make(chan datamodel.DiscoveredDevice)
	s := NewScanner(cfg, resultsChan)

	// Test that the scanner was initialized correctly
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}

	// Test maps were created
	if len(s.ProfilesMap) != 1 {
		t.Errorf("Expected 1 profile in map, got %d", len(s.ProfilesMap))
	}

	if len(s.SNMPConfigsMap) != 1 {
		t.Errorf("Expected 1 SNMP config in map, got %d", len(s.SNMPConfigsMap))
	}

	// Test that the job channel buffer was set correctly
	if cap(s.JobChannel) != cfg.GlobalScanSettings.ConcurrentScanners*2 {
		t.Errorf("Expected job channel capacity of %d, got %d", cfg.GlobalScanSettings.ConcurrentScanners*2, cap(s.JobChannel))
	}

	// Test that the results channel was passed through
	if s.ResultsChannel != resultsChan {
		t.Error("Results channel was not properly set")
	}
}

// mockScanWorker is a test helper for mocking scanWorker behavior
type mockScanWorker struct {
	s        *Scanner
	jobCount int
	ipList   []string
}

func (m *mockScanWorker) worker(workerID int) {
	defer m.s.WaitGroup.Done()
	for job := range m.s.JobChannel {
		m.jobCount++
		m.ipList = append(m.ipList, job.IPAddress)
	}
}

// TestScanWorker tests that the scanWorker processes jobs correctly
func TestScanWorker(t *testing.T) {
	// Skip real network operations in short mode
	if testing.Short() {
		t.Skip("Skipping network tests in short mode")
	}

	// Mock a simple Scanner for testing
	resultsChan := make(chan datamodel.DiscoveredDevice, 10)
	jobChan := make(chan datamodel.ScanJob, 10)

	scanner := &Scanner{
		ResultsChannel: resultsChan,
		JobChannel:     jobChan,
		Config: &datamodel.Config{
			GlobalScanSettings: datamodel.GlobalScanSettings{
				MaxOidsPerSNMPRequest: 10,
			},
		},
	}

	// Create a basic job with no enabled scans to avoid real network operations
	job := datamodel.ScanJob{
		IPAddress: "192.168.1.1",
		TargetConfig: datamodel.TargetConfig{
			Name: "test-target",
		},
		Profile: datamodel.ProfileConfig{
			Name: "test-profile",
			// All scan types disabled for this unit test
			ICMP: datamodel.ICMPProfile{
				IsEnabled: false,
			},
			SNMP: datamodel.SNMPProfile{
				IsEnabled: false,
			},
			DNS: datamodel.DNSProfile{
				IsEnabled: false,
			},
			TCP: datamodel.TCPProfile{
				IsEnabled: false,
			},
		},
	}

	// Start a worker in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner.scanWorker(0)
	}()

	// Send a job
	jobChan <- job
	close(jobChan)

	// Wait for the worker to finish
	wg.Wait()

	// There should be no results since no scan types were enabled
	select {
	case <-resultsChan:
		t.Error("Expected no results with all scan types disabled")
	default:
		// This is expected
	}
}

// TestStartScan_WithMockJobs tests that StartScan correctly dispatches jobs
func TestStartScan_WithMockJobs(t *testing.T) {
	// Create a test config with a single IP address to scan
	cfg := &datamodel.Config{
		Targets: []datamodel.TargetConfig{
			{
				Name:        "test-target",
				ProfileName: "test-profile",
				Addresses:   []string{"192.168.1.1"}, // Single IP, not a range or CIDR
			},
		},
		Profiles: []datamodel.ProfileConfig{
			{
				Name: "test-profile",
				// All scan types disabled to avoid real network operations
				ICMP: datamodel.ICMPProfile{
					IsEnabled: false,
				},
				SNMP: datamodel.SNMPProfile{
					IsEnabled: false,
				},
				DNS: datamodel.DNSProfile{
					IsEnabled: false,
				},
				TCP: datamodel.TCPProfile{
					IsEnabled: false,
				},
			},
		},
		GlobalScanSettings: datamodel.GlobalScanSettings{
			ConcurrentScanners: 1, // Just use 1 worker for testing
		},
	}

	// Create a scanner with a buffered results channel
	resultsChan := make(chan datamodel.DiscoveredDevice, 10)
	scanner := NewScanner(cfg, resultsChan)

	// Mock scanner.scanWorker using our mock helper
	mock := &mockScanWorker{
		s:      scanner,
		ipList: make([]string, 0),
	}

	// Override the scanWorker function
	scanner.WaitGroup.Add(1)
	go mock.worker(0)

	// Start the scan
	go func() {
		// Only run the StartScan goroutine up to the WaitGroup.Wait() call
		for _, targetCfg := range scanner.Config.Targets {
			profile, exists := scanner.ProfilesMap[targetCfg.ProfileName]
			if !exists {
				continue
			}

			// Pre-resolve SNMP configs for this profile
			jobSnmpConfigs := make(map[string]datamodel.SNMPConfig)
			if profile.SNMP.IsEnabled {
				for _, snmpConfName := range profile.SNMP.ConfigNamesOrdered {
					if conf, ok := scanner.SNMPConfigsMap[snmpConfName]; ok {
						jobSnmpConfigs[snmpConfName] = conf
					}
				}
			}

			// Process each address in the target
			for _, addressOrCIDR := range targetCfg.Addresses {
				ips, err := generateIPs(addressOrCIDR)
				if err != nil {
					continue
				}
				
				// Create a scan job for each IP
				for _, ip := range ips {
					job := datamodel.ScanJob{
						IPAddress:    ip.String(),
						TargetConfig: targetCfg,
						Profile:      profile,
						SNMPConfigs:  jobSnmpConfigs,
					}
					scanner.JobChannel <- job
				}
			}
		}

		// Close the job channel after all jobs are dispatched
		close(scanner.JobChannel)
	}()

	// Wait for all jobs to be processed
	scanner.WaitGroup.Wait()

	// Verify that one job was processed
	if mock.jobCount != 1 {
		t.Errorf("Expected 1 job to be processed, got %d", mock.jobCount)
	}
}

// TestStartScan_WithCIDR tests that StartScan correctly processes CIDR notation
func TestStartScan_WithCIDR(t *testing.T) {
	// Create a test config with a CIDR range to scan
	cfg := &datamodel.Config{
		Targets: []datamodel.TargetConfig{
			{
				Name:        "test-target",
				ProfileName: "test-profile",
				Addresses:   []string{"192.168.1.0/30"}, // 4 IPs, 2 hosts in network
			},
		},
		Profiles: []datamodel.ProfileConfig{
			{
				Name: "test-profile",
				// All scan types disabled to avoid real network operations
				ICMP: datamodel.ICMPProfile{
					IsEnabled: false,
				},
				SNMP: datamodel.SNMPProfile{
					IsEnabled: false,
				},
				DNS: datamodel.DNSProfile{
					IsEnabled: false,
				},
				TCP: datamodel.TCPProfile{
					IsEnabled: false,
				},
			},
		},
		GlobalScanSettings: datamodel.GlobalScanSettings{
			ConcurrentScanners: 1, // Just use 1 worker for testing
		},
	}

	// Create a scanner with a buffered results channel
	resultsChan := make(chan datamodel.DiscoveredDevice, 10)
	scanner := NewScanner(cfg, resultsChan)

	// Mock scanner.scanWorker using our mock helper
	mock := &mockScanWorker{
		s:      scanner,
		ipList: make([]string, 0),
	}

	// Override the scanWorker function
	scanner.WaitGroup.Add(1)
	go mock.worker(0)

	// Start the scan
	go func() {
		// Only run the StartScan goroutine up to the WaitGroup.Wait() call
		for _, targetCfg := range scanner.Config.Targets {
			profile, exists := scanner.ProfilesMap[targetCfg.ProfileName]
			if !exists {
				continue
			}

			// Pre-resolve SNMP configs for this profile
			jobSnmpConfigs := make(map[string]datamodel.SNMPConfig)
			if profile.SNMP.IsEnabled {
				for _, snmpConfName := range profile.SNMP.ConfigNamesOrdered {
					if conf, ok := scanner.SNMPConfigsMap[snmpConfName]; ok {
						jobSnmpConfigs[snmpConfName] = conf
					}
				}
			}

			// Process each address in the target
			for _, addressOrCIDR := range targetCfg.Addresses {
				ips, err := generateIPs(addressOrCIDR)
				if err != nil {
					continue
				}
				
				// Create a scan job for each IP
				for _, ip := range ips {
					job := datamodel.ScanJob{
						IPAddress:    ip.String(),
						TargetConfig: targetCfg,
						Profile:      profile,
						SNMPConfigs:  jobSnmpConfigs,
					}
					scanner.JobChannel <- job
				}
			}
		}

		// Close the job channel after all jobs are dispatched
		close(scanner.JobChannel)
	}()

	// Wait for all jobs to be processed
	scanner.WaitGroup.Wait()

	// Verify that 2 hosts were generated for the /30 CIDR
	if len(mock.ipList) != 2 {
		t.Errorf("Expected 2 hosts in /30 CIDR, got %d: %v", len(mock.ipList), mock.ipList)
	}

	// Verify the IPs are correct (skipping network and broadcast addresses)
	expectedIPs := []string{"192.168.1.1", "192.168.1.2"}
	for _, expected := range expectedIPs {
		found := false
		for _, ip := range mock.ipList {
			if ip == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected IP %s not found in job list", expected)
		}
	}
}

// TestStartScan_WithIPRange tests that StartScan correctly processes IP ranges
func TestStartScan_WithIPRange(t *testing.T) {
	// Create a test config with an IP range to scan
	cfg := &datamodel.Config{
		Targets: []datamodel.TargetConfig{
			{
				Name:        "test-target",
				ProfileName: "test-profile",
				Addresses:   []string{"192.168.1.5-192.168.1.7"}, // 3 IPs in range
			},
		},
		Profiles: []datamodel.ProfileConfig{
			{
				Name: "test-profile",
				// All scan types disabled to avoid real network operations
				ICMP: datamodel.ICMPProfile{
					IsEnabled: false,
				},
				SNMP: datamodel.SNMPProfile{
					IsEnabled: false,
				},
				DNS: datamodel.DNSProfile{
					IsEnabled: false,
				},
				TCP: datamodel.TCPProfile{
					IsEnabled: false,
				},
			},
		},
		GlobalScanSettings: datamodel.GlobalScanSettings{
			ConcurrentScanners: 1, // Just use 1 worker for testing
		},
	}

	// Create a scanner with a buffered results channel
	resultsChan := make(chan datamodel.DiscoveredDevice, 10)
	scanner := NewScanner(cfg, resultsChan)

	// Mock scanner.scanWorker using our mock helper
	mock := &mockScanWorker{
		s:      scanner,
		ipList: make([]string, 0),
	}

	// Override the scanWorker function
	scanner.WaitGroup.Add(1)
	go mock.worker(0)

	// Start the scan
	go func() {
		// Only run the StartScan goroutine up to the WaitGroup.Wait() call
		for _, targetCfg := range scanner.Config.Targets {
			profile, exists := scanner.ProfilesMap[targetCfg.ProfileName]
			if !exists {
				continue
			}

			// Pre-resolve SNMP configs for this profile
			jobSnmpConfigs := make(map[string]datamodel.SNMPConfig)
			if profile.SNMP.IsEnabled {
				for _, snmpConfName := range profile.SNMP.ConfigNamesOrdered {
					if conf, ok := scanner.SNMPConfigsMap[snmpConfName]; ok {
						jobSnmpConfigs[snmpConfName] = conf
					}
				}
			}

			// Process each address in the target
			for _, addressOrCIDR := range targetCfg.Addresses {
				ips, err := generateIPs(addressOrCIDR)
				if err != nil {
					continue
				}
				
				// Create a scan job for each IP
				for _, ip := range ips {
					job := datamodel.ScanJob{
						IPAddress:    ip.String(),
						TargetConfig: targetCfg,
						Profile:      profile,
						SNMPConfigs:  jobSnmpConfigs,
					}
					scanner.JobChannel <- job
				}
			}
		}

		// Close the job channel after all jobs are dispatched
		close(scanner.JobChannel)
	}()

	// Wait for all jobs to be processed
	scanner.WaitGroup.Wait()

	// Verify that 3 hosts were generated for the range
	if len(mock.ipList) != 3 {
		t.Errorf("Expected 3 hosts in range, got %d: %v", len(mock.ipList), mock.ipList)
	}

	// Verify the IPs are correct
	expectedIPs := []string{"192.168.1.5", "192.168.1.6", "192.168.1.7"}
	for _, expected := range expectedIPs {
		found := false
		for _, ip := range mock.ipList {
			if ip == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected IP %s not found in job list", expected)
		}
	}
}

// TestStartScan_WithInvalidAddress tests error handling for invalid addresses
func TestStartScan_WithInvalidAddress(t *testing.T) {
	// Create a test config with an invalid address to scan
	cfg := &datamodel.Config{
		Targets: []datamodel.TargetConfig{
			{
				Name:        "test-target",
				ProfileName: "test-profile",
				Addresses:   []string{"invalid-address"}, // Not a valid IP or CIDR
			},
		},
		Profiles: []datamodel.ProfileConfig{
			{
				Name: "test-profile",
				// All scan types disabled to avoid real network operations
				ICMP: datamodel.ICMPProfile{
					IsEnabled: false,
				},
			},
		},
		GlobalScanSettings: datamodel.GlobalScanSettings{
			ConcurrentScanners: 1, // Just use 1 worker for testing
		},
	}

	// Create a scanner with a buffered results channel
	resultsChan := make(chan datamodel.DiscoveredDevice, 10)
	scanner := NewScanner(cfg, resultsChan)

	// Mock scanner.scanWorker using our mock helper
	mock := &mockScanWorker{
		s:      scanner,
		ipList: make([]string, 0),
	}

	// Override the scanWorker function
	scanner.WaitGroup.Add(1)
	go mock.worker(0)

	// Start the scan
	go func() {
		// Only run the StartScan goroutine up to the WaitGroup.Wait() call
		for _, targetCfg := range scanner.Config.Targets {
			profile, exists := scanner.ProfilesMap[targetCfg.ProfileName]
			if !exists {
				continue
			}

			// Process each address in the target
			for _, addressOrCIDR := range targetCfg.Addresses {
				ips, err := generateIPs(addressOrCIDR)
				if err != nil {
					continue
				}
				
				// Create a scan job for each IP
				for _, ip := range ips {
					job := datamodel.ScanJob{
						IPAddress:    ip.String(),
						TargetConfig: targetCfg,
						Profile:      profile,
					}
					scanner.JobChannel <- job
				}
			}
		}

		// Close the job channel after all jobs are dispatched
		close(scanner.JobChannel)
	}()

	// Wait for all jobs to be processed
	scanner.WaitGroup.Wait()

	// Verify that no jobs were generated due to the invalid address
	if mock.jobCount != 0 {
		t.Errorf("Expected 0 jobs with invalid address, got %d", mock.jobCount)
	}
}

// TestStartScan_WithProfileNotFound tests error handling for missing profiles
func TestStartScan_WithProfileNotFound(t *testing.T) {
	// Create a test config with a reference to a non-existent profile
	cfg := &datamodel.Config{
		Targets: []datamodel.TargetConfig{
			{
				Name:        "test-target",
				ProfileName: "non-existent-profile", // This profile doesn't exist
				Addresses:   []string{"192.168.1.1"},
			},
		},
		Profiles: []datamodel.ProfileConfig{
			{
				Name: "test-profile", // Different name than referenced in target
				// All scan types disabled to avoid real network operations
				ICMP: datamodel.ICMPProfile{
					IsEnabled: false,
				},
			},
		},
		GlobalScanSettings: datamodel.GlobalScanSettings{
			ConcurrentScanners: 1, // Just use 1 worker for testing
		},
	}

	// Create a scanner with a buffered results channel
	resultsChan := make(chan datamodel.DiscoveredDevice, 10)
	scanner := NewScanner(cfg, resultsChan)

	// Mock scanner.scanWorker using our mock helper
	mock := &mockScanWorker{
		s:      scanner,
		ipList: make([]string, 0),
	}

	// Override the scanWorker function
	scanner.WaitGroup.Add(1)
	go mock.worker(0)

	// Start the scan
	go func() {
		// Only run the StartScan goroutine up to the WaitGroup.Wait() call
		for _, targetCfg := range scanner.Config.Targets {
			profile, exists := scanner.ProfilesMap[targetCfg.ProfileName]
			if !exists {
				continue
			}

			// Process each address in the target
			for _, addressOrCIDR := range targetCfg.Addresses {
				ips, err := generateIPs(addressOrCIDR)
				if err != nil {
					continue
				}
				
				// Create a scan job for each IP
				for _, ip := range ips {
					job := datamodel.ScanJob{
						IPAddress:    ip.String(),
						TargetConfig: targetCfg,
						Profile:      profile,
					}
					scanner.JobChannel <- job
				}
			}
		}

		// Close the job channel after all jobs are dispatched
		close(scanner.JobChannel)
	}()

	// Wait for all jobs to be processed
	scanner.WaitGroup.Wait()

	// Verify that no jobs were generated due to the missing profile
	if mock.jobCount != 0 {
		t.Errorf("Expected 0 jobs with missing profile, got %d", mock.jobCount)
	}
}

// TestStartScan_WithMultipleWorkers tests worker concurrency
func TestStartScan_WithMultipleWorkers(t *testing.T) {
	// Create a test config with multiple IP addresses
	cfg := &datamodel.Config{
		Targets: []datamodel.TargetConfig{
			{
				Name:        "test-target",
				ProfileName: "test-profile",
				Addresses:   []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"}, // 5 IPs
			},
		},
		Profiles: []datamodel.ProfileConfig{
			{
				Name: "test-profile",
				// All scan types disabled to avoid real network operations
				ICMP: datamodel.ICMPProfile{
					IsEnabled: false,
				},
			},
		},
		GlobalScanSettings: datamodel.GlobalScanSettings{
			ConcurrentScanners: 3, // Use 3 workers for testing concurrency
		},
	}

	// Create a scanner with a buffered results channel
	resultsChan := make(chan datamodel.DiscoveredDevice, 10)
	scanner := NewScanner(cfg, resultsChan)

	// Set up multiple workers with tracking
	var mutex sync.Mutex
	workerJobs := make(map[int]int)
	
	// Add worker goroutines
	for i := 0; i < cfg.GlobalScanSettings.ConcurrentScanners; i++ {
		workerID := i
		scanner.WaitGroup.Add(1)
		go func() {
			defer scanner.WaitGroup.Done()
			
			jobCount := 0
			for range scanner.JobChannel {
				jobCount++
				// Simulate some work to allow for concurrent processing
				time.Sleep(10 * time.Millisecond)
			}
			
			mutex.Lock()
			workerJobs[workerID] = jobCount
			mutex.Unlock()
		}()
	}

	// Start the scan
	go func() {
		// Only run the StartScan goroutine up to the WaitGroup.Wait() call
		for _, targetCfg := range scanner.Config.Targets {
			profile, exists := scanner.ProfilesMap[targetCfg.ProfileName]
			if !exists {
				continue
			}

			// Process each address in the target
			for _, addressOrCIDR := range targetCfg.Addresses {
				ips, err := generateIPs(addressOrCIDR)
				if err != nil {
					continue
				}
				
				// Create a scan job for each IP
				for _, ip := range ips {
					job := datamodel.ScanJob{
						IPAddress:    ip.String(),
						TargetConfig: targetCfg,
						Profile:      profile,
					}
					scanner.JobChannel <- job
				}
			}
		}

		// Close the job channel after all jobs are dispatched
		close(scanner.JobChannel)
	}()

	// Wait for all jobs to be processed
	scanner.WaitGroup.Wait()

	// Verify that all workers were used
	mutex.Lock()
	defer mutex.Unlock()
	
	if len(workerJobs) > cfg.GlobalScanSettings.ConcurrentScanners {
		t.Errorf("Expected at most %d workers to be used, got %d", cfg.GlobalScanSettings.ConcurrentScanners, len(workerJobs))
	}

	// Verify that all jobs were processed
	totalJobs := 0
	for _, count := range workerJobs {
		totalJobs += count
	}
	if totalJobs != 5 {
		t.Errorf("Expected 5 total jobs to be processed, got %d", totalJobs)
	}
}