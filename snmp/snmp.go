// Package snmp handles all SNMP (Simple Network Management Protocol) interactions
// with target devices, supporting SNMP versions v1, v2c, and v3.
package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/logger"
	g "github.com/gosnmp/gosnmp"
)

// maskSensitiveString masks sensitive strings like passwords and community strings
// for logging purposes while preserving length information.
func maskSensitiveString(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 2 {
		return "**"
	}
	// Show first and last character, mask the rest
	return s[:1] + strings.Repeat("*", len(s)-2) + s[len(s)-1:]
}

// PerformQuery connects to an SNMP agent and retrieves specified OIDs.
func PerformQuery(ipAddress string, snmpConfig datamodel.SNMPConfig, oidsToQuery []string, maxOidsPerRequest int) (*datamodel.SNMPScanResult, error) {
	// Set up structured logging
	log := logger.WithModule("snmp")

	// Validate input parameters
	if ipAddress == "" {
		return nil, fmt.Errorf("empty IP address provided to SNMP query")
	}
	
	// Default timeout and retries if not provided
	timeoutSec := snmpConfig.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 5 // Default 5 second timeout
		log.Debug("Using default timeout", "ip", ipAddress, "timeout_seconds", timeoutSec)
	}
	
	retries := snmpConfig.Retries
	if retries < 0 {
		retries = 0 // Ensure retries is non-negative
		log.Debug("Corrected negative retries value", "ip", ipAddress, "retries", retries)
	}
	
	// Create SNMP parameters
	params := &g.GoSNMP{
		Target:    ipAddress,
		Port:      161, // Standard SNMP port
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Retries:   retries,
	}
	
	log.Debug("Configuring SNMP query", "ip", ipAddress, "version", snmpConfig.Version, "timeout", timeoutSec, "retries", retries)

	// Configure SNMP parameters based on version
	switch strings.ToLower(snmpConfig.Version) {
	case "v1":
		params.Version = g.Version1
		params.Community = snmpConfig.Community
		log.Debug("Configured SNMPv1", "ip", ipAddress, "community", maskSensitiveString(snmpConfig.Community))
	case "v2c":
		params.Version = g.Version2c
		params.Community = snmpConfig.Community
		log.Debug("Configured SNMPv2c", "ip", ipAddress, "community", maskSensitiveString(snmpConfig.Community))
	case "v3":
		params.Version = g.Version3
		params.SecurityModel = g.UserSecurityModel
		
		// Ensure context name is not nil
		if snmpConfig.ContextName != "" {
			params.ContextName = snmpConfig.ContextName
		}

		// Check if username is provided for SNMPv3
		if snmpConfig.Username == "" {
			log.Warn("Empty username for SNMPv3 configuration", "ip", ipAddress, "config", snmpConfig.Name)
		}
		
		usmParams := &g.UsmSecurityParameters{
			UserName: snmpConfig.Username,
		}
		
		log.Debug("Configuring SNMPv3", "ip", ipAddress, "username", snmpConfig.Username, "securityLevel", snmpConfig.SecurityLevel)

		secLevel := strings.ToLower(snmpConfig.SecurityLevel)
		// Map security level string to gosnmp.SnmpV3MsgFlags with fallback
		switch secLevel {
		case "noauthnopriv":
			params.MsgFlags = g.NoAuthNoPriv
		case "authnopriv":
			params.MsgFlags = g.AuthNoPriv
		case "authpriv":
			params.MsgFlags = g.AuthPriv
		case "": // No security level specified
			log.Warn("No SNMPv3 security level specified, defaulting to noAuthNoPriv", "ip", ipAddress)
			params.MsgFlags = g.NoAuthNoPriv
			secLevel = "noauthnopriv" // Update for later reference
		default:
			log.Error("Invalid SNMPv3 security level", "ip", ipAddress, "security_level", snmpConfig.SecurityLevel)
			return nil, fmt.Errorf("invalid SNMPv3 security_level: %s", snmpConfig.SecurityLevel)
		}

		log.Debug("SNMPv3 security level configured", "ip", ipAddress, "security_level", secLevel)

		// Authentication protocol
		if params.MsgFlags == g.AuthNoPriv || params.MsgFlags == g.AuthPriv {
			// Check for empty auth password
			if snmpConfig.AuthPassword == "" {
				log.Error("Empty authentication password for SNMPv3", 
					"ip", ipAddress, 
					"security_level", secLevel, 
					"requires_auth", true)
				return nil, fmt.Errorf("SNMPv3 auth_password missing for security level %s", secLevel)
			}
			
			usmParams.AuthenticationPassphrase = snmpConfig.AuthPassword
			
			authProto := strings.ToUpper(snmpConfig.AuthProtocol)
			switch authProto {
			case "MD5":
				usmParams.AuthenticationProtocol = g.MD5
			case "SHA":
				usmParams.AuthenticationProtocol = g.SHA
			case "SHA224":
				usmParams.AuthenticationProtocol = g.SHA224
			case "SHA256":
				usmParams.AuthenticationProtocol = g.SHA256
			case "SHA384":
				usmParams.AuthenticationProtocol = g.SHA384
			case "SHA512":
				usmParams.AuthenticationProtocol = g.SHA512
			case "":
				log.Error("Missing authentication protocol for SNMPv3", 
					"ip", ipAddress, 
					"security_level", secLevel)
				return nil, fmt.Errorf("SNMPv3 auth_protocol missing for security level %s", secLevel)
			default:
				log.Error("Unsupported authentication protocol", 
					"ip", ipAddress, 
					"auth_protocol", authProto)
				return nil, fmt.Errorf("unsupported SNMPv3 auth_protocol: %s", authProto)
			}
			
			log.Debug("SNMPv3 authentication configured", 
				"ip", ipAddress, 
				"auth_protocol", authProto, 
				"auth_password", "******")
		}

		// Privacy protocol
		if params.MsgFlags == g.AuthPriv {
			// Check for empty privacy password
			if snmpConfig.PrivPassword == "" {
				log.Error("Empty privacy password for SNMPv3 authPriv", "ip", ipAddress)
				return nil, fmt.Errorf("SNMPv3 priv_password missing for security level authPriv")
			}
			
			usmParams.PrivacyPassphrase = snmpConfig.PrivPassword
			
			privProto := strings.ToUpper(snmpConfig.PrivProtocol)
			switch privProto {
			case "DES":
				usmParams.PrivacyProtocol = g.DES
			case "AES":
				usmParams.PrivacyProtocol = g.AES
			case "AES192":
				usmParams.PrivacyProtocol = g.AES192
			case "AES256":
				usmParams.PrivacyProtocol = g.AES256
			case "":
				log.Error("Missing privacy protocol for SNMPv3 authPriv", "ip", ipAddress)
				return nil, fmt.Errorf("SNMPv3 priv_protocol missing for security level authPriv")
			default:
				log.Error("Unsupported privacy protocol", "ip", ipAddress, "priv_protocol", privProto)
				return nil, fmt.Errorf("unsupported SNMPv3 priv_protocol: %s", privProto)
			}
			
			log.Debug("SNMPv3 privacy configured", 
				"ip", ipAddress, 
				"priv_protocol", privProto, 
				"priv_password", "******")
		}
		
		params.SecurityParameters = usmParams
	default:
		return nil, fmt.Errorf("unsupported SNMP version: %s", snmpConfig.Version)
	}

	// Initialize result structure before connection attempt
	scanResult := &datamodel.SNMPScanResult{
		SuccessfullyQueried: false,
		UsedSNMPConfigName:  snmpConfig.Name,
		QueriedData:         make(map[string]datamodel.SNMPValue),
	}

	// Connect to the SNMP agent
	log.Debug("Connecting to SNMP agent", "ip", ipAddress, "config", snmpConfig.Name)
	err := params.Connect()
	if err != nil {
		log.Error("SNMP connection failed", "ip", ipAddress, "error", err)
		return scanResult, fmt.Errorf("SNMP Connect() error to %s: %w", ipAddress, err)
	}
	
	// Ensure connection is closed when function exits
	defer func() {
		if params.Conn != nil {
			err := params.Conn.Close()
			if err != nil {
				log.Warn("Error closing SNMP connection", "ip", ipAddress, "error", err)
			}
		}
	}()

	// No OIDs to query, connection test only
	if len(oidsToQuery) == 0 {
		log.Debug("No OIDs to query, connection test only", "ip", ipAddress)
		scanResult.SuccessfullyQueried = true
		return scanResult, nil
	}

	// Validate and handle OID batching
	if maxOidsPerRequest <= 0 {
		maxOidsPerRequest = 60 // Default if not specified
		log.Debug("Using default maxOidsPerRequest", "ip", ipAddress, "max_oids", maxOidsPerRequest)
	} else if maxOidsPerRequest > 100 {
		// Cap at a reasonable maximum to prevent potential issues
		log.Warn("Capping excessive maxOidsPerRequest", "ip", ipAddress, "requested", maxOidsPerRequest, "capped_to", 100)
		maxOidsPerRequest = 100
	}

	// Process OIDs in batches
	for i := 0; i < len(oidsToQuery); i += maxOidsPerRequest {
		// Calculate batch range with bounds checking
		end := i + maxOidsPerRequest
		if end > len(oidsToQuery) {
			end = len(oidsToQuery)
		}
		batchOids := oidsToQuery[i:end]
		
		// Validate batch OIDs before sending
		for idx, oid := range batchOids {
			if oid == "" {
				log.Warn("Skipping empty OID in batch", "ip", ipAddress, "batch", i/maxOidsPerRequest, "index", idx)
				batchOids[idx] = "1.3.6.1.2.1.1.1.0" // Use sysDescr as a safe placeholder
			}
		}
		
		batchNum := i/maxOidsPerRequest
		log.Debug("Sending SNMP GET batch", 
			"ip", ipAddress, 
			"batch", batchNum, 
			"oids_count", len(batchOids),
			"start_idx", i,
			"end_idx", end-1)

		// Perform the SNMP GET with error handling
		packet, err := params.Get(batchOids)
		if err != nil {
			log.Error("SNMP GET failed for batch", 
				"ip", ipAddress, 
				"batch", batchNum, 
				"error", err)
				
			// Return partial results if we've already received some data
			if scanResult.SuccessfullyQueried {
				log.Warn("Partial data received before error, returning partial results", 
					"ip", ipAddress, 
					"data_points", len(scanResult.QueriedData))
				return scanResult, nil
			}
			
			// Otherwise report the error
			return scanResult, fmt.Errorf("SNMP Get() error for %s (batch %d): %w", ipAddress, batchNum, err)
		}

		// If we've received a packet without error, mark query as successful
		scanResult.SuccessfullyQueried = true
		
		// Safety check for nil packet
		if packet == nil {
			log.Warn("Received nil packet from SNMP GET", "ip", ipAddress, "batch", batchNum)
			continue
		}

		// Process returned variables with safety checks
		log.Debug("Processing SNMP response variables", 
			"ip", ipAddress, 
			"batch", batchNum, 
			"variables_count", len(packet.Variables))
			
		for vIdx, variable := range packet.Variables {
			if variable.Name == "" {
				log.Warn("Skipping variable with empty OID", "ip", ipAddress, "batch", batchNum, "var_idx", vIdx)
				continue
			}
			
			// Trim leading dot if present for consistency
			oidStr := strings.TrimPrefix(variable.Name, ".")
			var valueStr interface{}
			var typeStr string = variable.Type.String() // Use gosnmp's string representation
			var oidError string = ""

			// Convert values based on their type with safety checks
			switch variable.Type {
			case g.OctetString:
				if bytes, ok := variable.Value.([]byte); ok {
					valueStr = string(bytes)
				} else {
					log.Warn("Invalid OctetString value type", 
						"ip", ipAddress, 
						"oid", oidStr, 
						"actual_type", fmt.Sprintf("%T", variable.Value))
					valueStr = fmt.Sprintf("%v", variable.Value)
					oidError = "type_conversion_error"
				}
			case g.Integer, g.Counter32, g.Gauge32, g.TimeTicks, g.Counter64, g.Uinteger32:
				// Use safe conversion via gosnmp's utility
				valueStr = g.ToBigInt(variable.Value).String()
			case g.ObjectIdentifier:
				if str, ok := variable.Value.(string); ok {
					valueStr = str
				} else {
					log.Warn("Invalid ObjectIdentifier value type", 
						"ip", ipAddress, 
						"oid", oidStr, 
						"actual_type", fmt.Sprintf("%T", variable.Value))
					valueStr = fmt.Sprintf("%v", variable.Value)
					oidError = "type_conversion_error"
				}
			case g.IPAddress:
				if str, ok := variable.Value.(string); ok {
					valueStr = str
				} else {
					log.Warn("Invalid IPAddress value type", 
						"ip", ipAddress, 
						"oid", oidStr, 
						"actual_type", fmt.Sprintf("%T", variable.Value))
					valueStr = fmt.Sprintf("%v", variable.Value)
					oidError = "type_conversion_error"
				}
			case g.Null:
				valueStr = nil
			case g.NoSuchObject, g.NoSuchInstance, g.EndOfMibView:
				oidError = typeStr // Report the SNMP error
				valueStr = nil
				log.Debug("SNMP error response", "ip", ipAddress, "oid", oidStr, "error", typeStr)
			default:
				// For other types, convert to string representation safely
				if bytes, ok := variable.Value.([]byte); ok {
					valueStr = fmt.Sprintf("%x", bytes) // Hex representation
				} else {
					valueStr = fmt.Sprintf("%v", variable.Value) // Generic format
				}
			}

			// Protect against nil values that might cause panics in JSON marshaling
			if valueStr == nil {
				log.Debug("Null value for OID", "ip", ipAddress, "oid", oidStr, "type", typeStr)
			}

			// Store the value
			scanResult.QueriedData[oidStr] = datamodel.SNMPValue{
				Type:  typeStr,
				Value: valueStr,
				Error: oidError,
			}
		}
	}
	
	log.Info("SNMP query completed successfully", 
		"ip", ipAddress, 
		"config", snmpConfig.Name, 
		"oids_requested", len(oidsToQuery), 
		"oids_returned", len(scanResult.QueriedData))

	return scanResult, nil
}