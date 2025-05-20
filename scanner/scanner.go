// Package scanner handles the orchestration of the network discovery process.
package scanner

import (
	"fmt"
	"sync"
	"time"

	"go-netdiscover/datamodel"
	"go-netdiscover/dns"
	"go-netdiscover/icmp"
	"go-netdiscover/logger"
	"go-netdiscover/snmp"
)

// Scanner is the core orchestrator of the network discovery process.
type Scanner struct {
	Config         *datamodel.Config
	ResultsChannel chan datamodel.DiscoveredDevice // Channel to send results to output module
	JobChannel     chan datamodel.ScanJob          // Channel for distributing scan jobs to workers
	WaitGroup      sync.WaitGroup                  // To wait for all workers to finish
	
	// Pre-processed maps for efficiency
	ProfilesMap   map[string]datamodel.ProfileConfig
	SNMPConfigsMap map[string]datamodel.SNMPConfig
}

// NewScanner creates a new Scanner instance.
func NewScanner(cfg *datamodel.Config, resultsChan chan datamodel.DiscoveredDevice) *Scanner {
	// Create maps for efficient lookup
	profilesMap := make(map[string]datamodel.ProfileConfig)
	for _, p := range cfg.Profiles {
		profilesMap[p.Name] = p
	}

	snmpConfigsMap := make(map[string]datamodel.SNMPConfig)
	for _, sc := range cfg.SNMPConfigs {
		snmpConfigsMap[sc.Name] = sc
	}

	// Create a buffer for job channel based on concurrent scanners
	jobBufferSize := cfg.GlobalScanSettings.ConcurrentScanners * 2
	
	return &Scanner{
		Config:         cfg,
		ResultsChannel: resultsChan,
		JobChannel:     make(chan datamodel.ScanJob, jobBufferSize),
		ProfilesMap:    profilesMap,
		SNMPConfigsMap: snmpConfigsMap,
	}
}

// StartScan begins the scanning process.
func (s *Scanner) StartScan() {
	// Module-specific logger
	log := logger.WithModule("scanner")
	
	// Launch worker goroutines
	for i := 0; i < s.Config.GlobalScanSettings.ConcurrentScanners; i++ {
		s.WaitGroup.Add(1)
		go s.scanWorker(i)
	}

	// Generate and dispatch scan jobs
	for _, targetCfg := range s.Config.Targets {
		profile, exists := s.ProfilesMap[targetCfg.ProfileName]
		if !exists {
			log.Error("Profile not found for target", "profile", targetCfg.ProfileName, "target", targetCfg.Name)
			continue
		}

		// Pre-resolve SNMP configs for this profile
		jobSnmpConfigs := make(map[string]datamodel.SNMPConfig)
		if profile.SNMP.IsEnabled {
			for _, snmpConfName := range profile.SNMP.ConfigNamesOrdered {
				if conf, ok := s.SNMPConfigsMap[snmpConfName]; ok {
					jobSnmpConfigs[snmpConfName] = conf
				} else {
					log.Error("SNMP config not found", "config", snmpConfName, "profile", profile.Name)
				}
			}
		}

		// Process each address in the target
		for _, addressOrCIDR := range targetCfg.Addresses {
			ips, err := generateIPs(addressOrCIDR)
			if err != nil {
				log.Error("Failed to generate IPs", "address", addressOrCIDR, "error", err)
				continue
			}

			log.Debug("Generated IPs for scanning", "address", addressOrCIDR, "count", len(ips))
			
			// Create a scan job for each IP
			for _, ip := range ips {
				job := datamodel.ScanJob{
					IPAddress:    ip.String(),
					TargetConfig: targetCfg,
					Profile:      profile,
					SNMPConfigs:  jobSnmpConfigs,
				}
				s.JobChannel <- job
			}
		}
	}

	// Close the job channel after all jobs are dispatched
	close(s.JobChannel)
	
	// Wait for all workers to finish
	s.WaitGroup.Wait()
	
	// Close the results channel to signal the output module
	close(s.ResultsChannel)
	
	log.Info("Scan completed")
}

// scanWorker processes scan jobs.
func (s *Scanner) scanWorker(workerID int) {
	defer s.WaitGroup.Done()
	
	// Worker-specific logger
	log := logger.WithModule("scanner.worker").With("worker_id", workerID)

	for job := range s.JobChannel {
		// Initialize a discovered device structure
		discoveredDevice := datamodel.DiscoveredDevice{
			IPAddress:   job.IPAddress,
			TargetName:  job.TargetConfig.Name,
			ProfileName: job.Profile.Name,
			Timestamp:   time.Now().Format(time.RFC3339),
			Errors:      make([]string, 0),
		}
		var responded bool = false
		
		log.Debug("Processing host", "ip", job.IPAddress, "target", job.TargetConfig.Name)

		// 1. ICMP Scan
		if job.Profile.ICMP.IsEnabled {
			log.Debug("Performing ICMP scan", "ip", job.IPAddress)
			icmpRes, err := icmp.PerformPing(job.IPAddress, job.Profile.ICMP)
			if err != nil {
				errMsg := fmt.Sprintf("ICMP error: %v", err)
				log.Error("ICMP scan failed", "ip", job.IPAddress, "error", err)
				discoveredDevice.Errors = append(discoveredDevice.Errors, errMsg)
			}
			if icmpRes != nil {
				log.Debug("ICMP scan complete", 
					"ip", job.IPAddress, 
					"reachable", icmpRes.IsReachable, 
					"sent", icmpRes.PacketsSent, 
					"received", icmpRes.PacketsReceived)
				discoveredDevice.ICMPResult = icmpRes
				if icmpRes.IsReachable {
					responded = true
				}
			}
		}

		// Determine if we should skip remaining scans based on ICMP results
		shouldSkipRemaining := job.Profile.ICMP.IsEnabled && 
							  job.Profile.ICMP.SkipIfUnreachable && 
							  discoveredDevice.ICMPResult != nil && 
							  !discoveredDevice.ICMPResult.IsReachable
							  
		if shouldSkipRemaining {
			log.Debug("Skipping further scans due to ICMP unreachability", "ip", job.IPAddress)
		}

		// 2. SNMP Scan
		if job.Profile.SNMP.IsEnabled && !shouldSkipRemaining {
			log.Debug("Performing SNMP scan", "ip", job.IPAddress)
			
			for _, snmpConfName := range job.Profile.SNMP.ConfigNamesOrdered {
				snmpConf, ok := job.SNMPConfigs[snmpConfName]
				if !ok {
					errMsg := fmt.Sprintf("SNMP config '%s' not found in job context", snmpConfName)
					log.Error("SNMP config missing", "ip", job.IPAddress, "config", snmpConfName)
					discoveredDevice.Errors = append(discoveredDevice.Errors, errMsg)
					continue
				}

				log.Debug("Trying SNMP config", "ip", job.IPAddress, "config", snmpConfName)
				snmpRes, err := snmp.PerformQuery(job.IPAddress, snmpConf, job.Profile.SNMP.OIDsToQuery, s.Config.GlobalScanSettings.MaxOidsPerSNMPRequest)
				if err != nil {
					errMsg := fmt.Sprintf("SNMP query with '%s' failed: %v", snmpConfName, err)
					log.Error("SNMP query failed", "ip", job.IPAddress, "config", snmpConfName, "error", err)
					discoveredDevice.Errors = append(discoveredDevice.Errors, errMsg)
					continue
				}

				if snmpRes != nil && snmpRes.SuccessfullyQueried {
					log.Debug("SNMP query successful", "ip", job.IPAddress, "config", snmpConfName, "oids_count", len(snmpRes.QueriedData))
					discoveredDevice.SNMPResult = snmpRes
					responded = true // Device responded to SNMP
					break // Successfully queried with this config
				} else if snmpRes != nil {
					log.Debug("SNMP query partial results", "ip", job.IPAddress, "config", snmpConfName)
					discoveredDevice.SNMPResult = snmpRes // Store partial results
					responded = true // Device responded but may not have provided useful data
				}
			}
		}

		// 3. DNS Lookup
		if job.Profile.DNS.IsEnabled && !shouldSkipRemaining {
			log.Debug("Performing DNS lookups", "ip", job.IPAddress)
			
			// Determine DNS servers to use
			dnsServersToUse := job.Profile.DNS.DNSServers
			if len(dnsServersToUse) == 0 {
				dnsServersToUse = s.Config.GlobalScanSettings.DefaultDNSServers
			}

			dnsRes, errs := dns.PerformLookups(job.IPAddress, job.Profile.DNS, dnsServersToUse)
			if len(errs) > 0 {
				for _, e := range errs {
					errMsg := fmt.Sprintf("DNS error: %v", e)
					log.Error("DNS lookup error", "ip", job.IPAddress, "error", e)
					discoveredDevice.Errors = append(discoveredDevice.Errors, errMsg)
				}
			}
			if dnsRes != nil {
				// Check if any actual data was found
				if (job.Profile.DNS.DoReverseLookup && len(dnsRes.PTRRecords) > 0) ||
				   (job.Profile.DNS.DoForwardLookupIfReverseFound && len(dnsRes.ForwardLookupResults) > 0) {
					log.Debug("DNS lookups found records", 
						"ip", job.IPAddress, 
						"ptr_count", len(dnsRes.PTRRecords), 
						"forward_count", len(dnsRes.ForwardLookupResults))
					responded = true
				}
				discoveredDevice.DNSResult = dnsRes
			}
		}

		// Send to results channel only if the device responded in some way
		if responded {
			log.Debug("Device responded, sending to results channel", "ip", job.IPAddress)
			s.ResultsChannel <- discoveredDevice
		} else {
			log.Debug("Device did not respond, skipping", "ip", job.IPAddress)
		}
	}
}