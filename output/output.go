// Package output is responsible for presenting the results of the network discovery,
// handling real-time terminal UI and writing discovered device information to a JSON file.
package output

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
)

// OutputManager handles the presentation of discovery results.
type OutputManager struct {
	ResultsChannel       <-chan datamodel.DiscoveredDevice // Receives results from scanner
	ConfiguredOutputPath string                            // Path for the JSON output file
	AllDiscoveredDevices []datamodel.DiscoveredDevice      // Stores all devices for final JSON output
	Mutex                sync.Mutex                        // To protect AllDiscoveredDevices and stats

	// Terminal UI related fields
	TotalIPsToScan       int // Needs to be estimated or passed by the scanner
	ScannedIPsCount      int // Total IPs scanned (both responsive and non-responsive)
	RespondedIPsCount    int // Count of IPs that responded to at least one scan method
	LastNDevices         []datamodel.DiscoveredDevice // For displaying last N discovered devices
	MaxLastNDevices      int                          // Configurable N, e.g., 5 or 10
	StartTime            time.Time
	UIUpdateInterval     time.Duration

	// Control channel for stopping the UI updater goroutine
	doneChan    chan struct{}
	uiWaitGroup sync.WaitGroup
}

// NewOutputManager creates a new OutputManager instance.
func NewOutputManager(resultsChan <-chan datamodel.DiscoveredDevice, outputPath string, totalIPsEstimate int) *OutputManager {
	return &OutputManager{
		ResultsChannel:       resultsChan,
		ConfiguredOutputPath: outputPath,
		AllDiscoveredDevices: make([]datamodel.DiscoveredDevice, 0),
		TotalIPsToScan:       totalIPsEstimate,
		MaxLastNDevices:      5,
		UIUpdateInterval:     time.Second * 1,
		StartTime:            time.Now(),
		doneChan:             make(chan struct{}),
	}
}

// Start begins the output processing, launching the UI updater and listening for results.
func (om *OutputManager) Start() {
	om.uiWaitGroup.Add(1)
	go om.runTerminalUIUpdater()

	for device := range om.ResultsChannel {
		om.Mutex.Lock()
		om.ScannedIPsCount++
		
		// Only count responsive devices for the discovered count
		if device.Responded {
			om.RespondedIPsCount++
			
			// Update Last N Devices only for responsive devices
			om.LastNDevices = append([]datamodel.DiscoveredDevice{device}, om.LastNDevices...)
			if len(om.LastNDevices) > om.MaxLastNDevices {
				om.LastNDevices = om.LastNDevices[:om.MaxLastNDevices]
			}
		}
		
		// Store all devices for the final JSON output
		om.AllDiscoveredDevices = append(om.AllDiscoveredDevices, device)
		om.Mutex.Unlock()
	}

	// All results processed
	close(om.doneChan)    // Signal UI updater to stop
	om.uiWaitGroup.Wait() // Wait for UI to clean up

	om.WriteJSONOutput()

	// Final terminal output
	om.clearTerminal()
	fmt.Println("Scan Complete.")
	fmt.Printf("Total IPs Scanned: %d\n", om.ScannedIPsCount)
	fmt.Printf("Total Devices Discovered: %d\n", om.RespondedIPsCount)
	fmt.Printf("Results saved to: %s\n", om.ConfiguredOutputPath)
}

// runTerminalUIUpdater periodically updates the terminal UI with scan statistics.
func (om *OutputManager) runTerminalUIUpdater() {
	defer om.uiWaitGroup.Done()
	ticker := time.NewTicker(om.UIUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			om.Mutex.Lock()
			scanned := om.ScannedIPsCount
			responded := om.RespondedIPsCount
			total := om.TotalIPsToScan
			lastN := make([]datamodel.DiscoveredDevice, len(om.LastNDevices)) // Create a copy
			copy(lastN, om.LastNDevices)
			startTime := om.StartTime
			om.Mutex.Unlock()

			om.clearTerminal()

			// Calculate Progress based on all scanned IPs, not just responsive ones
			progressPercent := 0.0
			if total > 0 {
				progressPercent = (float64(scanned) / float64(total)) * 100
			}
			fmt.Printf("Progress: [%-50s] %.2f%%\n", om.renderProgressBar(progressPercent), progressPercent)
			fmt.Printf("Scanned: %d / %d IPs\n", scanned, total)
			fmt.Printf("Responsive: %d IPs (%.1f%%)\n", responded, calculatePercentage(responded, scanned))

			// Calculate Elapsed Time & ETA
			elapsed := time.Since(startTime)
			fmt.Printf("Elapsed: %s\n", elapsed.Round(time.Second))

			if scanned > 0 && total > scanned {
				ipsPerSecond := float64(scanned) / elapsed.Seconds()
				if ipsPerSecond > 0 {
					remainingIPs := total - scanned
					etaSeconds := float64(remainingIPs) / ipsPerSecond
					etaDuration := time.Duration(etaSeconds * float64(time.Second))
					fmt.Printf("ETA: %s\n", etaDuration.Round(time.Second))
				} else {
					fmt.Println("ETA: Calculating...")
				}
			} else if scanned == total && total > 0 {
				fmt.Println("ETA: Done.")
			} else {
				fmt.Println("ETA: N/A")
			}

			fmt.Println("\nLast Discovered Devices:")
			if len(lastN) == 0 {
				fmt.Println("  (None yet)")
			}
			for i, dev := range lastN {
				// Display key info about the device
				displayName := dev.IPAddress
				if dev.DNSResult != nil && len(dev.DNSResult.PTRRecords) > 0 {
					displayName = fmt.Sprintf("%s (%s)", dev.IPAddress, dev.DNSResult.PTRRecords[0])
				} else if dev.SNMPResult != nil && dev.SNMPResult.QueriedData != nil {
					// Try to display sysName if available
					sysNameOID := "1.3.6.1.2.1.1.5.0" // sysName
					if val, ok := dev.SNMPResult.QueriedData[sysNameOID]; ok && val.Error == "" {
						displayName = fmt.Sprintf("%s (%v)", dev.IPAddress, val.Value)
					} else {
						// If sysName not available, try sysDescr
						sysDescrOID := "1.3.6.1.2.1.1.1.0" // sysDescr
						if val, ok := dev.SNMPResult.QueriedData[sysDescrOID]; ok && val.Error == "" {
							displayName = fmt.Sprintf("%s (%s)", dev.IPAddress, om.truncateString(fmt.Sprintf("%v", val.Value), 30))
						}
					}
				}
				fmt.Printf("  %d. %s\n", i+1, displayName)
			}

		case <-om.doneChan:
			// Perform one final draw before exiting
			om.clearTerminal()
			fmt.Println("Finishing UI updates...")
			return
		}
	}
}

// calculatePercentage calculates a percentage, handling division by zero
func calculatePercentage(part, total int) float64 {
	if total == 0 {
		return 0.0
	}
	return (float64(part) / float64(total)) * 100.0
}

// clearTerminal clears the terminal screen (or moves cursor to clean area).
func (om *OutputManager) clearTerminal() {
	// Use ANSI escape code to clear screen and move cursor to top-left
	fmt.Print("\033[H\033[2J")
}

// renderProgressBar creates a simple text-based progress bar.
func (om *OutputManager) renderProgressBar(percentage float64) string {
	barLength := 50
	filledLength := int(float64(barLength) * percentage / 100)
	bar := ""
	for i := 0; i < filledLength; i++ {
		bar += "="
	}
	for i := 0; i < barLength-filledLength; i++ {
		bar += " "
	}
	return bar
}

// truncateString shortens a string if it's longer than specified length.
func (om *OutputManager) truncateString(str string, num int) string {
	if len(str) > num {
		if num > 3 {
			return str[0:num-3] + "..."
		}
		return str[0:num]
	}
	return str
}

// WriteJSONOutput writes discovered devices to a JSON file.
func (om *OutputManager) WriteJSONOutput() {
	om.Mutex.Lock()
	devicesCopy := make([]datamodel.DiscoveredDevice, len(om.AllDiscoveredDevices))
	copy(devicesCopy, om.AllDiscoveredDevices) // Work on a copy
	om.Mutex.Unlock()

	// Filter to only include devices that responded unless all are empty
	responsiveDevices := make([]datamodel.DiscoveredDevice, 0)
	for _, device := range devicesCopy {
		if device.Responded {
			responsiveDevices = append(responsiveDevices, device)
		}
	}

	// Only write responsive devices to the JSON output
	if len(responsiveDevices) == 0 {
		fmt.Println("No responsive devices discovered to write to JSON.")
		// Write an empty array to the file
		jsonData, _ := json.MarshalIndent([]datamodel.DiscoveredDevice{}, "", "  ")
		err := os.WriteFile(om.ConfiguredOutputPath, jsonData, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing empty JSON output to %s: %v\n", om.ConfiguredOutputPath, err)
		}
		return
	}

	// Sanitize floating point values to avoid JSON marshalling errors with -Inf, +Inf, NaN
	for i := range responsiveDevices {
		if responsiveDevices[i].ICMPResult != nil {
			// Handle RTT_ms special values
			if responsiveDevices[i].ICMPResult.RTT_ms < 0 || 
			   math.IsInf(responsiveDevices[i].ICMPResult.RTT_ms, 0) || 
			   math.IsNaN(responsiveDevices[i].ICMPResult.RTT_ms) {
				responsiveDevices[i].ICMPResult.RTT_ms = 0
			}
		}
		if responsiveDevices[i].TCPResult != nil {
			// Handle ResponseTime special values
			if responsiveDevices[i].TCPResult.ResponseTime < 0 || 
			   math.IsInf(responsiveDevices[i].TCPResult.ResponseTime, 0) || 
			   math.IsNaN(responsiveDevices[i].TCPResult.ResponseTime) {
				responsiveDevices[i].TCPResult.ResponseTime = 0
			}
		}
	}

	jsonData, err := json.MarshalIndent(responsiveDevices, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling results to JSON: %v\n", err)
		return
	}

	err = os.WriteFile(om.ConfiguredOutputPath, jsonData, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing JSON output to %s: %v\n", om.ConfiguredOutputPath, err)
	}
}