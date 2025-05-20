// Package snmp handles all SNMP (Simple Network Management Protocol) interactions
// with target devices, supporting SNMP versions v1, v2c, and v3.
package snmp

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	g "github.com/gosnmp/gosnmp"
	"github.com/lukeod/gonetdisco/datamodel"
	"github.com/lukeod/gonetdisco/logger"
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

	// Initialize result structure before connection attempt
	scanResult := &datamodel.SNMPScanResult{
		SuccessfullyQueried: false,
		UsedSNMPConfigName:  snmpConfig.Name,
		QueriedData:         make(map[string]datamodel.SNMPValue),
	}

	// Create SNMP parameters
	params, err := createSNMPParameters(ipAddress, snmpConfig, log)
	if err != nil {
		return scanResult, err
	}

	// Connect to the SNMP agent
	log.Debug("Connecting to SNMP agent", "ip", ipAddress, "config", snmpConfig.Name)
	err = params.Connect()
	if err != nil {
		log.Error("SNMP connection failed", "ip", ipAddress, "error", err)
		return scanResult, fmt.Errorf("SNMP Connect() error to %s: %w", ipAddress, err)
	}

	// Ensure connection is closed when function exits
	defer closeConnection(params, ipAddress, log)

	// No OIDs to query, connection test only
	if len(oidsToQuery) == 0 {
		log.Debug("No OIDs to query, connection test only", "ip", ipAddress)
		scanResult.SuccessfullyQueried = true
		return scanResult, nil
	}

	// Validate and handle OID batching
	maxOidsPerRequest = validateMaxOidsPerRequest(maxOidsPerRequest, ipAddress, log)

	// Process OIDs in batches
	err = processBatchedOIDs(params, oidsToQuery, maxOidsPerRequest, scanResult, ipAddress, log)
	if err != nil {
		return scanResult, err
	}

	log.Info("SNMP query completed successfully",
		"ip", ipAddress,
		"config", snmpConfig.Name,
		"oids_requested", len(oidsToQuery),
		"oids_returned", len(scanResult.QueriedData))

	return scanResult, nil
}

// closeConnection safely closes an SNMP connection
func closeConnection(params *g.GoSNMP, ipAddress string, log *slog.Logger) {
	if params.Conn != nil {
		err := params.Conn.Close()
		if err != nil {
			log.Warn("Error closing SNMP connection", "ip", ipAddress, "error", err)
		}
	}
}

// processBatchedOIDs processes OIDs in batches to avoid overwhelming the SNMP agent
func processBatchedOIDs(params *g.GoSNMP, oidsToQuery []string, maxOidsPerRequest int, scanResult *datamodel.SNMPScanResult, ipAddress string, log *slog.Logger) error {
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

		batchNum := i / maxOidsPerRequest
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
				return nil
			}

			// Otherwise report the error
			return fmt.Errorf("SNMP Get() error for %s (batch %d): %w", ipAddress, batchNum, err)
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

		processResponseVariables(packet.Variables, scanResult, ipAddress, batchNum, log)
	}
	return nil
}

// processResponseVariables handles the response variables from an SNMP query
func processResponseVariables(variables []g.SnmpPDU, scanResult *datamodel.SNMPScanResult, ipAddress string, batchNum int, log *slog.Logger) {
	for vIdx, variable := range variables {
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
		valueStr, oidError = convertSnmpValue(variable, oidStr, ipAddress, log)

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

// convertSnmpValue converts an SNMP value based on its type
func convertSnmpValue(variable g.SnmpPDU, oidStr, ipAddress string, log *slog.Logger) (interface{}, string) {
	typeStr := variable.Type.String()
	var valueStr interface{}
	var oidError string

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

	return valueStr, oidError
}

// validateMaxOidsPerRequest ensures the max OIDs per request is within acceptable bounds
func validateMaxOidsPerRequest(maxOidsPerRequest int, ipAddress string, log *slog.Logger) int {
	if maxOidsPerRequest <= 0 {
		maxOidsPerRequest = 60 // Default if not specified
		log.Debug("Using default maxOidsPerRequest", "ip", ipAddress, "max_oids", maxOidsPerRequest)
	} else if maxOidsPerRequest > 100 {
		// Cap at a reasonable maximum to prevent potential issues
		log.Warn("Capping excessive maxOidsPerRequest", "ip", ipAddress, "requested", maxOidsPerRequest, "capped_to", 100)
		maxOidsPerRequest = 100
	}
	return maxOidsPerRequest
}

// createSNMPParameters creates and configures the SNMP parameters based on the provided configuration
func createSNMPParameters(ipAddress string, snmpConfig datamodel.SNMPConfig, log *slog.Logger) (*g.GoSNMP, error) {
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
		Target:  ipAddress,
		Port:    161, // Standard SNMP port
		Timeout: time.Duration(timeoutSec) * time.Second,
		Retries: retries,
	}

	log.Debug("Configuring SNMP query", "ip", ipAddress, "version", snmpConfig.Version, "timeout", timeoutSec, "retries", retries)

	// Configure SNMP parameters based on version
	switch strings.ToLower(snmpConfig.Version) {
	case "v1":
		return configureV1(params, snmpConfig, ipAddress, log)
	case "v2c":
		return configureV2c(params, snmpConfig, ipAddress, log)
	case "v3":
		return configureV3(params, snmpConfig, ipAddress, log)
	default:
		return nil, fmt.Errorf("unsupported SNMP version: %s", snmpConfig.Version)
	}
}

// configureV1 configures SNMPv1 parameters
func configureV1(params *g.GoSNMP, snmpConfig datamodel.SNMPConfig, ipAddress string, log *slog.Logger) (*g.GoSNMP, error) {
	params.Version = g.Version1
	params.Community = snmpConfig.Community
	log.Debug("Configured SNMPv1", "ip", ipAddress, "community", maskSensitiveString(snmpConfig.Community))
	return params, nil
}

// configureV2c configures SNMPv2c parameters
func configureV2c(params *g.GoSNMP, snmpConfig datamodel.SNMPConfig, ipAddress string, log *slog.Logger) (*g.GoSNMP, error) {
	params.Version = g.Version2c
	params.Community = snmpConfig.Community
	log.Debug("Configured SNMPv2c", "ip", ipAddress, "community", maskSensitiveString(snmpConfig.Community))
	return params, nil
}

// configureV3 configures SNMPv3 parameters
func configureV3(params *g.GoSNMP, snmpConfig datamodel.SNMPConfig, ipAddress string, log *slog.Logger) (*g.GoSNMP, error) {
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

	// Configure security level
	secLevel, err := configureV3SecurityLevel(params, snmpConfig.SecurityLevel, ipAddress, log)
	if err != nil {
		return nil, err
	}

	// Configure authentication if needed
	if params.MsgFlags == g.AuthNoPriv || params.MsgFlags == g.AuthPriv {
		err = configureV3Authentication(usmParams, snmpConfig, secLevel, ipAddress, log)
		if err != nil {
			return nil, err
		}
	}

	// Configure privacy if needed
	if params.MsgFlags == g.AuthPriv {
		err = configureV3Privacy(usmParams, snmpConfig, ipAddress, log)
		if err != nil {
			return nil, err
		}
	}

	params.SecurityParameters = usmParams
	return params, nil
}

// configureV3SecurityLevel configures the security level for SNMPv3
func configureV3SecurityLevel(params *g.GoSNMP, configSecLevel, ipAddress string, log *slog.Logger) (string, error) {
	secLevel := strings.ToLower(configSecLevel)
	
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
		log.Error("Invalid SNMPv3 security level", "ip", ipAddress, "security_level", configSecLevel)
		return "", fmt.Errorf("invalid SNMPv3 security_level: %s", configSecLevel)
	}

	log.Debug("SNMPv3 security level configured", "ip", ipAddress, "security_level", secLevel)
	return secLevel, nil
}

// configureV3Authentication configures the authentication for SNMPv3
func configureV3Authentication(usmParams *g.UsmSecurityParameters, snmpConfig datamodel.SNMPConfig, secLevel, ipAddress string, log *slog.Logger) error {
	// Check for empty auth password
	if snmpConfig.AuthPassword == "" {
		log.Error("Empty authentication password for SNMPv3",
			"ip", ipAddress,
			"security_level", secLevel,
			"requires_auth", true)
		return fmt.Errorf("SNMPv3 auth_password missing for security level %s", secLevel)
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
		return fmt.Errorf("SNMPv3 auth_protocol missing for security level %s", secLevel)
	default:
		log.Error("Unsupported authentication protocol",
			"ip", ipAddress,
			"auth_protocol", authProto)
		return fmt.Errorf("unsupported SNMPv3 auth_protocol: %s", authProto)
	}

	log.Debug("SNMPv3 authentication configured",
		"ip", ipAddress,
		"auth_protocol", authProto,
		"auth_password", "******")
	
	return nil
}

// configureV3Privacy configures the privacy for SNMPv3
func configureV3Privacy(usmParams *g.UsmSecurityParameters, snmpConfig datamodel.SNMPConfig, ipAddress string, log *slog.Logger) error {
	// Check for empty privacy password
	if snmpConfig.PrivPassword == "" {
		log.Error("Empty privacy password for SNMPv3 authPriv", "ip", ipAddress)
		return fmt.Errorf("SNMPv3 priv_password missing for security level authPriv")
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
		return fmt.Errorf("SNMPv3 priv_protocol missing for security level authPriv")
	default:
		log.Error("Unsupported privacy protocol", "ip", ipAddress, "priv_protocol", privProto)
		return fmt.Errorf("unsupported SNMPv3 priv_protocol: %s", privProto)
	}

	log.Debug("SNMPv3 privacy configured",
		"ip", ipAddress,
		"priv_protocol", privProto,
		"priv_password", "******")
	
	return nil
}