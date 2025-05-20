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

	// Parse command-line flags and initialize the logger
	args := parseCommandLineFlags()

	// Load the configuration file
	cfg := loadConfigurationFile(args.configFile)

	// Determine the output path
	outputPath := determineOutputPath(cfg, args.outputFile)

	// Estimate the total number of IPs for UI
	totalIPsEstimate := estimateTotalIPs(cfg)

	// Initialize components and start the scanning process
	runNetworkDiscovery(cfg, outputPath, totalIPsEstimate)

	logger.Info("Discovery process completed")
	fmt.Println("gonetdisco finished.")
}

// CommandLineArgs contains the parsed command-line arguments
type CommandLineArgs struct {
	configFile string
	outputFile string
	verbosity  int
}

// parseCommandLineFlags parses the command-line flags and initializes the logger
func parseCommandLineFlags() CommandLineArgs {
	configFile := flag.String("config", "", "Path to the YAML configuration file (required)")
	outputFile := flag.String("output", "", "Path to the JSON output file (overrides config)")
	verbosity := flag.Int("verbosity", 1, "Logging verbosity level (0=errors only, 1=warnings, 2=info, 3=debug)")
	flag.Parse()

	// Initialize logger based on verbosity flag
	initializeLogger(*verbosity)

	if *configFile == "" {
		logger.Error("Configuration file path is required")
		fmt.Fprintln(os.Stderr, "Error: Configuration file path is required.")
		flag.Usage()
		os.Exit(1)
	}

	return CommandLineArgs{
		configFile: *configFile,
		outputFile: *outputFile,
		verbosity:  *verbosity,
	}
}

// initializeLogger initializes the logger based on the verbosity level
func initializeLogger(verbosity int) {
	var logLevel logger.LogLevel
	switch verbosity {
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
}

// loadConfigurationFile loads the configuration from the specified file
func loadConfigurationFile(configFile string) *datamodel.Config {
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		logger.Error("Failed to load configuration", "file", configFile, "error", err)
		fmt.Fprintf(os.Stderr, "Error loading configuration from %s: %v\n", configFile, err)
		os.Exit(1)
	}
	logger.Info("Configuration loaded successfully", "file", configFile)
	return cfg
}

// determineOutputPath determines the output path based on configuration and command-line flag
func determineOutputPath(cfg *datamodel.Config, outputFileFlag string) string {
	outputPath := cfg.GlobalScanSettings.DefaultOutputPath
	if outputFileFlag != "" {
		outputPath = outputFileFlag
		logger.Debug("Output path overridden by flag", "path", outputPath)
	} else {
		logger.Debug("Using output path from config", "path", outputPath)
	}
	if outputPath == "" {
		logger.Error("Output path not defined")
		fmt.Fprintln(os.Stderr, "Error: Output path is not defined via flag or configuration.")
		os.Exit(1)
	}
	return outputPath
}

// estimateTotalIPs estimates the total number of IPs to scan for progress reporting
func estimateTotalIPs(cfg *datamodel.Config) int {
	totalIPsEstimate := 0
	for _, target := range cfg.Targets {
		for _, addrStr := range target.Addresses {
			totalIPsEstimate += estimateIPsInAddress(addrStr)
		}
	}

	// Use a minimum value for a reasonable visual display
	if totalIPsEstimate <= 0 && len(cfg.Targets) > 0 {
		totalIPsEstimate = 1
		logger.Warn("Could not estimate IP count, using placeholder value")
	}

	return totalIPsEstimate
}

// estimateIPsInAddress estimates the number of IPs in a single address string (IP, CIDR, or range)
func estimateIPsInAddress(addrStr string) int {
	// Check if it's a single IP
	if ip := net.ParseIP(addrStr); ip != nil && ip.To4() != nil {
		return 1
	}

	// Check if it's a CIDR block
	if _, ipNet, err := net.ParseCIDR(addrStr); err == nil && ipNet.IP.To4() != nil {
		return estimateIPsInCIDR(ipNet)
	}

	// Check if it's an IP range
	if parts := strings.Split(addrStr, "-"); len(parts) == 2 {
		return estimateIPsInRange(parts[0], parts[1], addrStr)
	}

	// Invalid format, log and return 0
	logger.Warn("Could not parse address", "address", addrStr)
	return 0
}

// estimateIPsInCIDR estimates the number of usable host IPs in a CIDR block
func estimateIPsInCIDR(ipNet *net.IPNet) int {
	prefixLen, totalBits := ipNet.Mask.Size()
	if totalBits != 32 {
		// Not IPv4
		return 0
	}

	if prefixLen == 32 {
		// /32 network (single host)
		return 1
	} else if prefixLen == 31 {
		// /31 network (point-to-point, RFC 3021)
		return 2
	} else if prefixLen < 31 {
		// /30 and smaller masks
		hostBits := 32 - prefixLen
		numAddressesInBlock := 1 << hostBits
		if numAddressesInBlock > 2 {
			// Subtract network and broadcast addresses
			return numAddressesInBlock - 2
		}
	}
	return 0
}

// estimateIPsInRange estimates the number of IPs in an IP range (start-end)
func estimateIPsInRange(startStr, endStr, fullRange string) int {
	startIP := net.ParseIP(startStr)
	endIP := net.ParseIP(endStr)

	if startIP != nil && endIP != nil && startIP.To4() != nil && endIP.To4() != nil {
		// Convert to uint32 for subtraction
		start := ipToUint32(startIP.To4())
		end := ipToUint32(endIP.To4())

		if start <= end {
			return int(end - start + 1)
		} else {
			logger.Warn("Invalid IP range", "range", fullRange, "reason", "start > end")
		}
	} else {
		logger.Warn("Could not parse IP range", "range", fullRange)
	}
	return 0
}

// runNetworkDiscovery initializes components and runs the network discovery process
func runNetworkDiscovery(cfg *datamodel.Config, outputPath string, totalIPsEstimate int) {
	// Initialize components
	resultsChan := createResultsChannel(cfg)
	outputMgr := output.NewOutputManager(resultsChan, outputPath, totalIPsEstimate)
	scannerInstance := scanner.NewScanner(cfg, resultsChan)

	// Start scan process
	logger.Info("Starting network discovery", "config", outputPath, "output", outputPath)
	fmt.Printf("Starting network discovery. Output: %s\n", outputPath)
	fmt.Println("Press Ctrl+C to interrupt (Note: graceful shutdown implementation pending)")

	// Start scanner in a goroutine
	go runScannerWithRecovery(scannerInstance)

	// Start output manager (blocks until resultsChan is closed)
	outputMgr.Start()
}

// createResultsChannel creates the channel for sending discovered devices
func createResultsChannel(cfg *datamodel.Config) chan datamodel.DiscoveredDevice {
	resultsChanBufferSize := cfg.GlobalScanSettings.ConcurrentScanners * 2
	if resultsChanBufferSize <= 0 {
		resultsChanBufferSize = 50 // Default if concurrency is too low
	}
	return make(chan datamodel.DiscoveredDevice, resultsChanBufferSize)
}

// runScannerWithRecovery runs the scanner with panic recovery
func runScannerWithRecovery(scannerInstance *scanner.Scanner) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in scanner goroutine", "error", r)
			fmt.Fprintf(os.Stderr, "Panic in scanner goroutine: %v\n", r)
		}
	}()
	scannerInstance.StartScan()
}
