// Package main is the entry point for the gonetdisco application.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/lukeod/gonetdisco/config"
	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/logger"
	"github.com/lukeod/gonetdisco/output"
	"github.com/lukeod/gonetdisco/scanner"
)

// ipToUint32 converts an IPv4 address to uint32 for arithmetic operations
func ipToUint32(ip net.IP) uint32 {
	if len(ip) == 16 {
		// This is an IPv4 address in IPv6 format, extract the IPv4 part
		ip = ip[12:16]
	}
	
	var result uint32
	result += uint32(ip[0]) << 24
	result += uint32(ip[1]) << 16
	result += uint32(ip[2]) << 8
	result += uint32(ip[3])
	
	return result
}

func main() {
	// Utilize all available CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Parse command-line arguments
	configFile := flag.String("config", "", "Path to the YAML configuration file (required)")
	outputFile := flag.String("output", "", "Path to the JSON output file (overrides config)")
	
	// Logging options
	verbosity := flag.Int("verbosity", 1, "Logging verbosity level (0=errors only, 1=warnings, 2=info, 3=debug)")
	flag.Parse()
	
	// Initialize logger based on verbosity flag
	var logLevel logger.LogLevel
	switch *verbosity {
	case 0:
		logLevel = logger.LevelError
	case 1:
		logLevel = logger.LevelWarn
	case 2:
		logLevel = logger.LevelInfo
	case 3:
		logLevel = logger.LevelDebug
	default:
		logLevel = logger.LevelInfo
	}
	logger.Init(logLevel)

	if *configFile == "" {
		logger.Error("Configuration file path is required")
		fmt.Fprintln(os.Stderr, "Error: Configuration file path is required.")
		flag.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		logger.Error("Failed to load configuration", "file", *configFile, "error", err)
		fmt.Fprintf(os.Stderr, "Error loading configuration from %s: %v\n", *configFile, err)
		os.Exit(1)
	}
	logger.Info("Configuration loaded successfully", "file", *configFile)

	// Determine output path
	determinedOutputPath := cfg.GlobalScanSettings.DefaultOutputPath
	if *outputFile != "" {
		determinedOutputPath = *outputFile
		logger.Debug("Output path overridden by flag", "path", determinedOutputPath)
	} else {
		logger.Debug("Using output path from config", "path", determinedOutputPath)
	}
	if determinedOutputPath == "" {
		logger.Error("Output path not defined")
		fmt.Fprintln(os.Stderr, "Error: Output path is not defined via flag or configuration.")
		os.Exit(1)
	}

	// Estimate total IPs for UI
	totalIPsEstimate := 0
	for _, target := range cfg.Targets {
		for _, addrStr := range target.Addresses {
			if ip := net.ParseIP(addrStr); ip != nil && ip.To4() != nil {
				totalIPsEstimate++
			} else if _, ipNet, err := net.ParseCIDR(addrStr); err == nil && ipNet.IP.To4() != nil {
				prefixLen, totalBits := ipNet.Mask.Size()
				if totalBits == 32 { // Ensure IPv4
					if prefixLen == 32 { // /32 network
						totalIPsEstimate += 1
					} else if prefixLen == 31 { // /31 network (point-to-point)
						totalIPsEstimate += 2
					} else if prefixLen < 31 { // /30 and smaller masks
						hostBits := 32 - prefixLen
						numAddressesInBlock := 1 << hostBits
						if numAddressesInBlock > 2 {
							totalIPsEstimate += numAddressesInBlock - 2
						}
					}
				}
			} else if parts := strings.Split(addrStr, "-"); len(parts) == 2 {
				// Try to handle as IP range
				startIP := net.ParseIP(parts[0])
				endIP := net.ParseIP(parts[1])
				
				if startIP != nil && endIP != nil && startIP.To4() != nil && endIP.To4() != nil {
					// Convert to uint32 for subtraction
					start := ipToUint32(startIP.To4())
					end := ipToUint32(endIP.To4())
					
					if start <= end {
						totalIPsEstimate += int(end - start + 1)
					} else {
						logger.Warn("Invalid IP range", "range", addrStr, "reason", "start > end")
					}
				} else {
					logger.Warn("Could not parse IP range", "range", addrStr)
				}
			} else {
				// Invalid format, skip for now
				logger.Warn("Could not parse address", "address", addrStr)
			}
		}
	}
	
	// Use a minimum value for a reasonable visual display
	if totalIPsEstimate <= 0 && len(cfg.Targets) > 0 {
		totalIPsEstimate = 1
		logger.Warn("Could not estimate IP count, using placeholder value")
	}

	// Initialize components
	resultsChanBufferSize := cfg.GlobalScanSettings.ConcurrentScanners * 2
	if resultsChanBufferSize <= 0 {
		resultsChanBufferSize = 50 // Default if concurrency is too low
	}
	resultsChan := make(chan datamodel.DiscoveredDevice, resultsChanBufferSize)
	
	outputMgr := output.NewOutputManager(resultsChan, determinedOutputPath, totalIPsEstimate)
	scannerInstance := scanner.NewScanner(cfg, resultsChan)

	// Start scan process
	logger.Info("Starting network discovery", "config", *configFile, "output", determinedOutputPath)
	fmt.Printf("Starting network discovery. Config: %s, Output: %s\n", *configFile, determinedOutputPath)
	fmt.Println("Press Ctrl+C to interrupt (Note: graceful shutdown implementation pending)")
	
	// Start scanner in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in scanner goroutine", "error", r)
				fmt.Fprintf(os.Stderr, "Panic in scanner goroutine: %v\n", r)
			}
		}()
		scannerInstance.StartScan()
	}()

	// Start output manager (blocks until resultsChan is closed)
	outputMgr.Start()
	
	logger.Info("Discovery process completed")
	fmt.Println("gonetdisco finished.")
}