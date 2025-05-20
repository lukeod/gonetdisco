package tcp

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/logger"
)

// ScanTCP performs a TCP port scan on the specified IP address
func ScanTCP(ctx context.Context, ip string, config *datamodel.TCPConfig) (*datamodel.TCPScanResult, error) {
	result := &datamodel.TCPScanResult{
		Reachable: false,
		OpenPorts: make(map[int]string),
	}

	logger.Debug(fmt.Sprintf("Starting TCP scan for %s", ip))

	if !config.Enabled || len(config.Ports) == 0 {
		logger.Debug(fmt.Sprintf("TCP scan disabled or no ports specified for %s", ip))
		return result, nil
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, port := range config.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Create the TCP address to connect to
			addr := fmt.Sprintf("%s:%d", ip, p)

			// Create a dialer with timeout
			dialer := net.Dialer{
				Timeout: time.Duration(config.Timeout) * time.Second,
			}

			// Try to connect
			startTime := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			scanDuration := time.Since(startTime)

			if err == nil {
				// Connection successful, port is open
				service := getServiceName(p) // Get common service name for this port

				// Calculate response time safely
				respTime := scanDuration.Seconds()
				if respTime < 0 || math.IsInf(respTime, 0) || math.IsNaN(respTime) {
					respTime = 0
				}
				
				mutex.Lock()
				result.Reachable = true
				result.OpenPorts[p] = service
				result.ResponseTime = respTime
				mutex.Unlock()

				logger.Debug(fmt.Sprintf("TCP port %d is open on %s (service: %s)", p, ip, service))
				conn.Close()
			} else {
				logger.Debug(fmt.Sprintf("TCP port %d is closed/filtered on %s: %v", p, ip, err))
			}
		}(port)
	}

	wg.Wait()
	return result, nil
}

// getServiceName returns a common service name for well-known ports
func getServiceName(port int) string {
	commonPorts := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		111:  "RPC",
		135:  "MSRPC",
		139:  "NetBIOS",
		143:  "IMAP",
		389:  "LDAP",
		443:  "HTTPS",
		445:  "SMB",
		636:  "LDAPS",
		993:  "IMAPS",
		995:  "POP3S",
		1433: "MSSQL",
		1521: "Oracle",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		5900: "VNC",
		8080: "HTTP-Proxy",
		8443: "HTTPS-Alt",
	}

	if service, ok := commonPorts[port]; ok {
		return service
	}
	return "unknown"
}