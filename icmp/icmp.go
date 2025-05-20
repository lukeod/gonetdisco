// Package icmp is responsible for performing ICMP "ping" operations to check
// host reachability and gather round-trip time (RTT) statistics.
package icmp

import (
	"fmt"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/logger"
	probing "github.com/prometheus-community/pro-bing"
)

// PerformPing sends ICMP echo requests to the target IP address.
// It stops after receiving the first successful response.
func PerformPing(ipAddress string, profile datamodel.ICMPProfile) (*datamodel.ICMPScanResult, error) {
	pinger, err := probing.NewPinger(ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create pinger for %s: %w", ipAddress, err)
	}

	// Always set count to a default high number - we'll stop when we get a response
	if profile.Retries > 0 {
		pinger.Count = profile.Retries
	} else {
		pinger.Count = 3 // Default if retries not specified
	}

	if profile.PacketSizeBytes > 0 {
		pinger.Size = profile.PacketSizeBytes
	}

	// Set timeout for the entire pinger.Run() operation
	if profile.TimeoutSeconds > 0 {
		pinger.Timeout = time.Duration(profile.TimeoutSeconds) * time.Second
	} else {
		defaultPacketTimeout := 2 * time.Second
		if pinger.Count > 0 {
			pinger.Timeout = (time.Duration(pinger.Count) * pinger.Interval) + defaultPacketTimeout
		} else {
			pinger.Timeout = defaultPacketTimeout * 5
		}
	}

	// Set privileged mode based on profile
	log := logger.WithModule("icmp")
	log.Debug("Configuring ping options", "ip", ipAddress, "privileged", profile.Privileged, "count", pinger.Count, "timeout", pinger.Timeout)
	pinger.SetPrivileged(profile.Privileged)

	var result datamodel.ICMPScanResult
	var pingerError error
	var firstResponseReceived bool

	// Add callbacks to track results
	pinger.OnRecv = func(pkt *probing.Packet) {
		log.Debug("Received ping response",
			"ip", pkt.IPAddr,
			"seq", pkt.Seq,
			"size", pkt.Nbytes,
			"rtt", pkt.Rtt.String(),
			"ttl", pkt.TTL)

		// Store the first successful response and stop pinging
		if !firstResponseReceived {
			firstResponseReceived = true

			// Create the result with just this packet
			result = datamodel.ICMPScanResult{
				IsReachable:       true,
				PacketsSent:       pkt.Seq,                                     // How many we sent before getting a response
				PacketsReceived:   1,                                           // We got exactly one response
				PacketLossPercent: float64(pkt.Seq-1) * 100 / float64(pkt.Seq), // Loss % based on packets sent before success
				RTT_ms:            float64(pkt.Rtt.Nanoseconds()) / 1e6,        // Single RTT value
			}

			// Stop pinging after the first successful response
			log.Debug("Stopping ping after first response", "ip", ipAddress)
			pinger.Stop()
		}
	}

	pinger.OnFinish = func(stats *probing.Statistics) {
		log.Debug("Ping statistics",
			"ip", stats.Addr,
			"sent", stats.PacketsSent,
			"received", stats.PacketsRecv,
			"duplicates", stats.PacketsRecvDuplicates,
			"loss_percent", stats.PacketLoss)

		// Only update the result if we haven't already received a response
		// This handles the case where all pings fail
		if !firstResponseReceived {
			result = datamodel.ICMPScanResult{
				IsReachable:       stats.PacketsRecv > 0,
				PacketsSent:       stats.PacketsSent,
				PacketsReceived:   stats.PacketsRecv,
				PacketLossPercent: stats.PacketLoss,
			}

			// Add RTT data if we have received packets (shouldn't happen with early stop)
			if stats.PacketsRecv > 0 {
				result.RTT_ms = float64(stats.MinRtt.Nanoseconds()) / 1e6 // Just use the min RTT
				log.Debug("Ping completed without early stop", "ip", ipAddress, "rtt_ms", result.RTT_ms)
			} else {
				log.Debug("Ping completed with no responses", "ip", ipAddress)
			}
		}
	}

	// Run the pinger
	log.Debug("Starting ping", "ip", ipAddress)
	pingerError = pinger.Run()

	if pingerError != nil {
		// If pinger.Run() errors, create a failure result if OnFinish didn't run
		if result.PacketsSent == 0 {
			result = datamodel.ICMPScanResult{
				IsReachable:       false,
				PacketsSent:       pinger.Count,
				PacketsReceived:   0,
				PacketLossPercent: 100.0,
			}
		}
		log.Error("Pinger execution failed", "ip", ipAddress, "error", pingerError)
		return &result, fmt.Errorf("pinger execution failed for %s: %w", ipAddress, pingerError)
	}

	log.Debug("Ping completed", "ip", ipAddress, "reachable", result.IsReachable)
	return &result, nil
}
