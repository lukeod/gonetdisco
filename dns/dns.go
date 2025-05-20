// Package dns is responsible for performing DNS lookups, specifically reverse DNS (PTR records)
// for IP addresses and forward DNS (A/AAAA records) for hostnames obtained from reverse lookups.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
)

// PerformLookups performs DNS lookups based on the profile.
func PerformLookups(ipAddress string, profile datamodel.DNSProfile, dnsServersToUse []string) (*datamodel.DNSScanResult, []error) {
	scanResult := &datamodel.DNSScanResult{
		PTRRecords:           make([]string, 0),
		ForwardLookupResults: make(map[string][]string),
	}
	var encounteredErrors []error

	// Set up resolver
	resolver := net.DefaultResolver
	dialerTimeout := time.Duration(profile.TimeoutSeconds) * time.Second

	// If custom DNS servers are provided, create a custom resolver
	if len(dnsServersToUse) > 0 {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Use the first DNS server in the list
				d := net.Dialer{
					Timeout: dialerTimeout,
				}
				// Ensure server address has a port
				serverAddr := dnsServersToUse[0]
				if !strings.Contains(serverAddr, ":") {
					serverAddr = net.JoinHostPort(serverAddr, "53")
				}
				return d.DialContext(ctx, "udp", serverAddr)
			},
		}
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), dialerTimeout)
	defer cancel()

	// 1. Reverse DNS Lookup (PTR)
	if profile.DoReverseLookup {
		ptrNames, err := resolver.LookupAddr(ctx, ipAddress)
		if err != nil {
			dnsErr := fmt.Errorf("reverse lookup for %s failed: %w", ipAddress, err)
			encounteredErrors = append(encounteredErrors, dnsErr)
		} else {
			for _, ptr := range ptrNames {
				// PTR records often end with a dot, trim it for consistency
				scanResult.PTRRecords = append(scanResult.PTRRecords, strings.TrimSuffix(ptr, "."))
			}
		}
	}

	// 2. Forward DNS Lookup (A/AAAA)
	if profile.DoForwardLookupIfReverseFound && len(scanResult.PTRRecords) > 0 {
		for _, hostname := range scanResult.PTRRecords {
			if hostname == "" {
				continue
			}
			
			forwardIps, err := resolver.LookupHost(ctx, hostname)
			if err != nil {
				dnsErr := fmt.Errorf("forward lookup for %s (from PTR %s) failed: %w", hostname, ipAddress, err)
				encounteredErrors = append(encounteredErrors, dnsErr)
			} else {
				scanResult.ForwardLookupResults[hostname] = forwardIps
			}
		}
	}

	return scanResult, encounteredErrors
}