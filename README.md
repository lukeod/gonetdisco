# GoNetDisco - Network Discovery Tool

GoNetDisco is a high-performance network discovery and inventory tool written in Go that combines ICMP, SNMP, and DNS techniques to discover and catalog devices on your network.

## Features

- **Fast Concurrent Scanning**: Configurable number of concurrent scanners for optimized performance
- **Multi-Protocol Support**: 
  - ICMP ping for availability detection
  - SNMP v1/v2c/v3 for device information gathering
  - DNS lookups (reverse and forward) for hostname resolution
  - TCP port scanning for service detection
- **Flexible Target Configuration**: Scan specific IP addresses, ranges, or CIDR notation
- **Profile-Based Scanning**: Define reusable scan profiles with different settings
- **Real-time Progress Display**: Terminal UI shows scan progress and discovered devices
- **JSON Output**: Export results to structured JSON files for further processing

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/gonetdisco.git
cd gonetdisco

# Build the binary
go build -o gonetdisco
```

## Quick Start

1. Create a configuration file or use the sample `config.yaml`
2. Run the scan:

```bash
./gonetdisco --config config.yaml
```

## Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--config` | Path to YAML configuration file | Required |
| `--output` | Path to JSON output file | Overrides config file setting |
| `--verbosity` | Logging level (0-3) | 1 |

Verbosity levels:
- 0: Errors only
- 1: Warnings and errors
- 2: Info, warnings, and errors
- 3: Debug, info, warnings, and errors

## Configuration File

GoNetDisco uses a YAML configuration file with the following structure:

```yaml
# Global settings
global:
  concurrentScanners: 100  # Number of parallel scanning threads
  outputPath: "output.json"  # Default output path
  maxOidsPerRequest: 10  # Maximum number of OIDs per SNMP request
  dnsServers:  # Optional custom DNS servers
    - "8.8.8.8"
    - "1.1.1.1"

# Target networks to scan
targets:
  - name: "Office Network"
    addresses: 
      - "192.168.1.0/24"
      - "192.168.2.10-192.168.2.50"
      - "10.0.0.1"
    profile: "default"

# SNMP configuration profiles
snmpConfigs:
  - name: "public-v2c"
    version: "2c"
    community: "public"
    
  - name: "secure-v3"
    version: "3"
    secLevel: "authPriv"
    userName: "admin"
    authProtocol: "SHA"
    authPassword: "authpassword"
    privProtocol: "AES"
    privPassword: "privpassword"

# Scan profiles
profiles:
  - name: "default"
    icmp:
      enabled: true
      timeout: 2  # seconds
      count: 1  # number of pings
    snmp:
      enabled: true
      config: "public-v2c"
      timeout: 5  # seconds
      oids:
        - "1.3.6.1.2.1.1.5.0"  # sysName
        - "1.3.6.1.2.1.1.1.0"  # sysDescr
    dns:
      enabled: true
      reverseLookup: true
      forwardLookup: true
```

### Configuration Elements

#### Global Settings

- `concurrentScanners`: Number of parallel scanning threads
- `outputPath`: Default path to save JSON output
- `maxOidsPerRequest`: Maximum OIDs per SNMP request
- `dnsServers`: Optional list of DNS servers to use

#### Targets

Each target consists of:
- `name`: Descriptive name
- `addresses`: List of IP addresses, ranges, or CIDR notation
- `profile`: Scan profile to use

#### SNMP Configurations

SNMP v1/v2c:
- `name`: Configuration profile name
- `version`: "1" or "2c"
- `community`: SNMP community string

SNMP v3:
- `name`: Configuration profile name
- `version`: "3"
- `secLevel`: Security level ("noAuthNoPriv", "authNoPriv", or "authPriv")
- `userName`: SNMPv3 username
- `authProtocol`: Authentication protocol ("MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512")
- `authPassword`: Authentication password
- `privProtocol`: Privacy protocol ("DES", "AES", "AES192", "AES256", "AES192C", "AES256C")
- `privPassword`: Privacy password

#### Scan Profiles

Each profile defines how to scan targets:

- ICMP settings:
  - `enabled`: Enable/disable ICMP scanning
  - `timeout`: Timeout in seconds
  - `count`: Number of ping attempts

- SNMP settings:
  - `enabled`: Enable/disable SNMP scanning
  - `config`: SNMP configuration profile to use
  - `timeout`: Timeout in seconds
  - `oids`: List of OIDs to query

- DNS settings:
  - `enabled`: Enable/disable DNS lookups
  - `reverseLookup`: Perform reverse (PTR) lookups
  - `forwardLookup`: Perform forward lookups to verify PTR records

- TCP settings:
  - `enabled`: Enable/disable TCP port scanning
  - `timeout`: Timeout in seconds for connection attempts
  - `ports`: List of port numbers to scan

## Output Format

GoNetDisco generates a JSON file with discovered devices:

```json
[
  {
    "ip": "192.168.1.1",
    "hostname": "router.example.com",
    "icmp": {
      "reachable": true,
      "rtt": 1.25
    },
    "snmp": {
      "reachable": true,
      "oids": {
        "1.3.6.1.2.1.1.5.0": "ROUTER01",
        "1.3.6.1.2.1.1.1.0": "Cisco IOS Software, C2900 Software..."
      }
    },
    "dns": {
      "ptr": "router.example.com",
      "forward": "192.168.1.1"
    },
    "tcp": {
      "reachable": true,
      "open_ports": {
        "22": "SSH",
        "80": "HTTP",
        "443": "HTTPS"
      },
      "response_time": 0.042
    }
  }
]
```

## Examples

### Basic LAN Scan

```yaml
global:
  concurrentScanners: 50
  outputPath: "lan_scan.json"

targets:
  - name: "LAN"
    addresses: 
      - "192.168.1.0/24"
    profile: "basic"

snmpConfigs:
  - name: "public"
    version: "2c"
    community: "public"

profiles:
  - name: "basic"
    icmp:
      enabled: true
      timeout: 1
    snmp:
      enabled: true
      config: "public"
    dns:
      enabled: true
      reverseLookup: true
    tcp:
      enabled: true
      timeout: 2
      ports:
        - 22
        - 80
        - 443
        - 3389
```

### Multiple Networks with Different Profiles

```yaml
global:
  concurrentScanners: 100
  outputPath: "network_inventory.json"

targets:
  - name: "Office Network"
    addresses: 
      - "10.1.0.0/16"
    profile: "full"
  
  - name: "Data Center"
    addresses:
      - "172.16.0.0/16"
    profile: "secure"

snmpConfigs:
  - name: "public"
    version: "2c"
    community: "public"
  
  - name: "secure"
    version: "3"
    secLevel: "authPriv"
    userName: "admin"
    authProtocol: "SHA"
    authPassword: "authpass"
    privProtocol: "AES"
    privPassword: "privpass"

profiles:
  - name: "full"
    icmp:
      enabled: true
    snmp:
      enabled: true
      config: "public"
      oids:
        - "1.3.6.1.2.1.1.5.0"  # sysName
        - "1.3.6.1.2.1.1.1.0"  # sysDescr
        - "1.3.6.1.2.1.1.6.0"  # sysLocation
    dns:
      enabled: true
    tcp:
      enabled: true
      timeout: 2
      ports:
        - 21
        - 22
        - 23
        - 25
        - 80
        - 443
        - 8080
      
  - name: "secure"
    icmp:
      enabled: true
    snmp:
      enabled: true
      config: "secure"
      oids:
        - "1.3.6.1.2.1.1.5.0"  # sysName
        - "1.3.6.1.2.1.1.1.0"  # sysDescr
    dns:
      enabled: true
    tcp:
      enabled: true
      timeout: 3
      ports:
        - 22
        - 443
        - 3306
        - 5432
```

## License

This project is licensed under the terms specified in the LICENSE file.