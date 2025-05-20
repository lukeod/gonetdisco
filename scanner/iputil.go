// Package scanner handles the orchestration of the scanning process
package scanner

import (
	"fmt"
	"net"
	"bytes"
	"strings"
)

// generateIPs converts an IP address string or CIDR notation into a slice of net.IP addresses
func generateIPs(addressOrCIDR string) ([]net.IP, error) {
	// First, try to parse as a single IP address
	ip := net.ParseIP(addressOrCIDR)
	if ip != nil {
		if ip.To4() != nil { // Ensure it's an IPv4 address
			return []net.IP{ip}, nil
		}
		return nil, fmt.Errorf("address '%s' is not a valid IPv4 address", addressOrCIDR)
	}

	// Next, try to parse as CIDR notation
	_, ipNet, err := net.ParseCIDR(addressOrCIDR)
	if err == nil {
		if ipNet.IP.To4() == nil { // Ensure it's an IPv4 CIDR
			return nil, fmt.Errorf("CIDR '%s' is not a valid IPv4 network", addressOrCIDR)
		}

		ips := make([]net.IP, 0)
		
		// Get network and broadcast addresses
		networkAddr, broadcastAddr := addressRange(ipNet)
		
		// Get prefix length
		prefixLen, totalBits := ipNet.Mask.Size()
		if totalBits != 32 { // Should be caught by To4() check above
			return nil, fmt.Errorf("CIDR '%s' is not an IPv4 network (totalBits != 32)", addressOrCIDR)
		}

		switch prefixLen {
		case 32: // /32 network (single host)
			ipToAdd := make(net.IP, len(networkAddr))
			copy(ipToAdd, networkAddr)
			ips = append(ips, ipToAdd)
		case 31: // /31 network (point-to-point, 2 hosts)
			ip1 := make(net.IP, len(networkAddr))
			copy(ip1, networkAddr)
			ips = append(ips, ip1)

			ip2 := make(net.IP, len(broadcastAddr))
			copy(ip2, broadcastAddr)
			ips = append(ips, ip2)
		default: // /30 and smaller masks
			// For regular networks, we scan all addresses except network and broadcast
			// First scannable host is networkAddr + 1
			currentIP := inc(networkAddr)

			// Iterate through all IPs up to but not including the broadcast address
			for !bytes.Equal(currentIP, broadcastAddr) {
				ipToAdd := make(net.IP, len(currentIP))
				copy(ipToAdd, currentIP)
				ips = append(ips, ipToAdd)
				currentIP = inc(currentIP)
			}
		}

		// Sanity check - we should have at least one IP for non-trivial CIDR blocks
		if len(ips) == 0 && prefixLen < 31 {
			return nil, fmt.Errorf("no scannable host IPv4 addresses were derived from CIDR '%s'", addressOrCIDR)
		}
		
		return ips, nil
	}

	// Try to parse as an IP range (e.g., "192.168.1.1-192.168.1.10")
	parts := strings.Split(addressOrCIDR, "-")
	if len(parts) == 2 {
		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP range format '%s': start or end IP is invalid", addressOrCIDR)
		}
		
		if startIP.To4() == nil || endIP.To4() == nil {
			return nil, fmt.Errorf("IP range '%s' must use IPv4 addresses", addressOrCIDR)
		}
		
		// Compare IPs to ensure start <= end
		if bytes.Compare(startIP.To4(), endIP.To4()) > 0 {
			return nil, fmt.Errorf("invalid IP range '%s': start IP must be <= end IP", addressOrCIDR)
		}
		
		ips := make([]net.IP, 0)
		currentIP := make(net.IP, len(startIP.To4()))
		copy(currentIP, startIP.To4())
		
		for {
			// Add current IP to list
			ipToAdd := make(net.IP, len(currentIP))
			copy(ipToAdd, currentIP)
			ips = append(ips, ipToAdd)
			
			// Stop if we've reached the end IP
			if bytes.Equal(currentIP, endIP.To4()) {
				break
			}
			
			// Increment to next IP
			currentIP = inc(currentIP)
		}
		
		return ips, nil
	}

	return nil, fmt.Errorf("invalid address, CIDR, or range format: %s", addressOrCIDR)
}

// addressRange returns the first and last addresses in a CIDR range
func addressRange(network *net.IPNet) (net.IP, net.IP) {
	// The first IP is just the network address
	firstIP := network.IP

	// The last IP is the network address OR NOT the mask
	prefixLen, bits := network.Mask.Size()
	if prefixLen == bits {
		// Special case: /32 CIDR
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)
		return firstIP, lastIP
	}

	// For other CIDRs, calculate the broadcast address
	lastIP := make([]byte, len(firstIP))
	for i := 0; i < len(firstIP); i++ {
		lastIP[i] = firstIP[i] | ^network.Mask[i]
	}
	
	return firstIP, lastIP
}

// inc increases an IP by one, returning a new []byte
func inc(ip net.IP) net.IP {
	incIP := make([]byte, len(ip))
	copy(incIP, ip)
	
	// Start from the end (least significant byte) and increment
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			// If we didn't wrap around, we're done
			break
		}
		// If we did wrap around, continue to the next byte
	}
	
	return incIP
}

// countIPsInCIDR returns the number of scannable IP addresses in a CIDR block
func countIPsInCIDR(addressOrCIDR string) (int, error) {
	ip := net.ParseIP(addressOrCIDR)
	if ip != nil {
		if ip.To4() != nil { // Ensure IPv4
			return 1, nil
		}
		return 0, fmt.Errorf("address '%s' is not a valid IPv4 address", addressOrCIDR)
	}

	_, ipNet, err := net.ParseCIDR(addressOrCIDR)
	if err == nil {
		if ipNet.IP.To4() == nil { // Ensure IPv4 CIDR
			return 0, fmt.Errorf("CIDR '%s' is not a valid IPv4 network", addressOrCIDR)
		}

		prefixLen, totalBits := ipNet.Mask.Size()
		if totalBits != 32 { // Should be caught by To4() check above
			return 0, fmt.Errorf("CIDR '%s' is not an IPv4 network (totalBits != 32)", addressOrCIDR)
		}

		// Calculate the number of scannable addresses based on prefix length
		switch prefixLen {
		case 32: // /32 network (single host)
			return 1, nil
		case 31: // /31 network (point-to-point, 2 hosts)
			return 2, nil
		default: // /30 and smaller masks
			// Total addresses is 2^(32-prefixLen)
			// Scannable hosts = Total addresses - 2 (network and broadcast)
			hostBits := 32 - prefixLen
			numAddressesInBlock := 1 << hostBits
			if numAddressesInBlock > 2 {
				return numAddressesInBlock - 2, nil
			}
			return 0, nil
		}
	}

	return 0, fmt.Errorf("invalid address or CIDR format: %s", addressOrCIDR)
}