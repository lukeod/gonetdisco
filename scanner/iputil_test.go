package scanner

import (
	"net"
	"reflect"
	"testing"
)

func TestGenerateIPs(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantIPs     []string
		wantErr     bool
		expectedErr string
	}{
		{
			name:    "Single IP address",
			input:   "192.168.1.1",
			wantIPs: []string{"192.168.1.1"},
			wantErr: false,
		},
		{
			name:    "CIDR /32 network (single host)",
			input:   "192.168.1.1/32",
			wantIPs: []string{"192.168.1.1"},
			wantErr: false,
		},
		{
			name:    "CIDR /31 network (point-to-point, 2 hosts)",
			input:   "192.168.1.0/31",
			wantIPs: []string{"192.168.1.0", "192.168.1.1"},
			wantErr: false,
		},
		{
			name:    "CIDR /30 network (4 IPs, 2 hosts)",
			input:   "192.168.1.0/30",
			wantIPs: []string{"192.168.1.1", "192.168.1.2"},
			wantErr: false,
		},
		{
			name:    "CIDR /29 network (8 IPs, 6 hosts)",
			input:   "192.168.1.0/29",
			wantIPs: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"},
			wantErr: false,
		},
		{
			name:    "IP range",
			input:   "192.168.1.5-192.168.1.10",
			wantIPs: []string{"192.168.1.5", "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10"},
			wantErr: false,
		},
		{
			name:        "IPv6 address (unsupported)",
			input:       "2001:db8::1",
			wantIPs:     nil,
			wantErr:     true,
			expectedErr: "address '2001:db8::1' is not a valid IPv4 address",
		},
		{
			name:        "Invalid input",
			input:       "not-an-ip",
			wantIPs:     nil,
			wantErr:     true,
			expectedErr: "invalid address, CIDR, or range format: not-an-ip",
		},
		{
			name:        "Invalid IP range (start > end)",
			input:       "192.168.1.10-192.168.1.5",
			wantIPs:     nil,
			wantErr:     true,
			expectedErr: "invalid IP range '192.168.1.10-192.168.1.5': start IP must be <= end IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := generateIPs(tt.input)
			
			// Check error condition
			if (err != nil) != tt.wantErr {
				t.Errorf("generateIPs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			// Check specific error message if expected
			if tt.wantErr && tt.expectedErr != "" && err != nil && err.Error() != tt.expectedErr {
				t.Errorf("generateIPs() error = %v, expected error %v", err, tt.expectedErr)
				return
			}
			
			if err != nil {
				return
			}
			
			// Convert net.IP slices to string slices for easier comparison
			gotIPStrs := make([]string, len(ips))
			for i, ip := range ips {
				gotIPStrs[i] = ip.String()
			}
			
			// Compare results
			if !reflect.DeepEqual(gotIPStrs, tt.wantIPs) {
				t.Errorf("generateIPs() = %v, want %v", gotIPStrs, tt.wantIPs)
			}
		})
	}
}

func TestCountIPsInCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name:    "Single IP address",
			input:   "192.168.1.1",
			want:    1,
			wantErr: false,
		},
		{
			name:    "CIDR /32 network (single host)",
			input:   "192.168.1.1/32",
			want:    1,
			wantErr: false,
		},
		{
			name:    "CIDR /31 network (point-to-point, 2 hosts)",
			input:   "192.168.1.0/31",
			want:    2,
			wantErr: false,
		},
		{
			name:    "CIDR /30 network (4 IPs, 2 hosts)",
			input:   "192.168.1.0/30",
			want:    2,
			wantErr: false,
		},
		{
			name:    "CIDR /29 network (8 IPs, 6 hosts)",
			input:   "192.168.1.0/29",
			want:    6,
			wantErr: false,
		},
		{
			name:    "CIDR /24 network (256 IPs, 254 hosts)",
			input:   "192.168.1.0/24",
			want:    254,
			wantErr: false,
		},
		{
			name:    "IPv6 address (unsupported)",
			input:   "2001:db8::1",
			want:    0,
			wantErr: true,
		},
		{
			name:    "Invalid input",
			input:   "not-an-ip",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := countIPsInCIDR(tt.input)
			
			// Check error condition
			if (err != nil) != tt.wantErr {
				t.Errorf("countIPsInCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if err != nil {
				return
			}
			
			// Compare results
			if count != tt.want {
				t.Errorf("countIPsInCIDR() = %v, want %v", count, tt.want)
			}
		})
	}
}

func TestAddressRange(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		wantFirst string
		wantLast  string
	}{
		{
			name:     "CIDR /32 network (single host)",
			cidr:     "192.168.1.1/32",
			wantFirst: "192.168.1.1",
			wantLast:  "192.168.1.1",
		},
		{
			name:     "CIDR /31 network (point-to-point, 2 hosts)",
			cidr:     "192.168.1.0/31",
			wantFirst: "192.168.1.0",
			wantLast:  "192.168.1.1",
		},
		{
			name:     "CIDR /30 network (4 IPs, 2 hosts)",
			cidr:     "192.168.1.0/30",
			wantFirst: "192.168.1.0",
			wantLast:  "192.168.1.3",
		},
		{
			name:     "CIDR /29 network (8 IPs, 6 hosts)",
			cidr:     "192.168.1.0/29",
			wantFirst: "192.168.1.0",
			wantLast:  "192.168.1.7",
		},
		{
			name:     "CIDR /24 network (256 IPs, 254 hosts)",
			cidr:     "192.168.1.0/24",
			wantFirst: "192.168.1.0",
			wantLast:  "192.168.1.255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.cidr, err)
			}
			
			first, last := addressRange(ipNet)
			
			if first.String() != tt.wantFirst {
				t.Errorf("addressRange() first = %v, want %v", first.String(), tt.wantFirst)
			}
			
			if last.String() != tt.wantLast {
				t.Errorf("addressRange() last = %v, want %v", last.String(), tt.wantLast)
			}
		})
	}
}

func TestInc(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "Normal increment",
			ip:   "192.168.1.1",
			want: "192.168.1.2",
		},
		{
			name: "Increment with rollover in last byte",
			ip:   "192.168.1.255",
			want: "192.168.2.0",
		},
		{
			name: "Increment with rollover in middle bytes",
			ip:   "192.168.255.255",
			want: "192.169.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP %s", tt.ip)
			}
			
			incIP := inc(ip)
			
			if incIP.String() != tt.want {
				t.Errorf("inc() = %v, want %v", incIP.String(), tt.want)
			}
		})
	}
}