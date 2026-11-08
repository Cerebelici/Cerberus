package identity

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// NetBIOSInfo represents identity details returned by a NetBIOS Node Status query.
type NetBIOSInfo struct {
	ComputerName string
	Workgroup    string
	UserName     string
	MAC          string
}

// QueryNetBIOS sends a standard NetBIOS Node Status query (UDP 137) with wildcard "*<00>"
// to unmask Windows and Samba computer and workgroup names.
func QueryNetBIOS(ctx context.Context, ip string, timeout time.Duration) (*NetBIOSInfo, error) {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}

	raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:137", ip))
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Build NetBIOS Node Status request packet:
	// Header (12 bytes)
	// Transaction ID: 0x1337
	// Flags: 0x0000 (Query)
	// Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
	// Question Name: 0x20 (32 bytes encoded "*<00>"), 0x00
	// Question Type: 0x0021 (NBSTAT)
	// Question Class: 0x0001 (IN)
	packet := make([]byte, 50)
	binary.BigEndian.PutUint16(packet[0:2], 0x1337) // Transaction ID
	binary.BigEndian.PutUint16(packet[2:4], 0x0000) // Flags
	binary.BigEndian.PutUint16(packet[4:6], 0x0001) // Questions = 1

	// Encode "*<00>" to 32 bytes RFC 1001/1002 representation:
	// '*' = 0x2A -> 'C' (0x43), 'K' (0x4B)
	// 15 spaces (0x20) -> 'C' (0x43), 'A' (0x41) x 15
	packet[12] = 0x20 // Length of name
	packet[13] = 'C'
	packet[14] = 'K'
	for i := 0; i < 15; i++ {
		packet[15+i*2] = 'C'
		packet[16+i*2] = 'A'
	}
	packet[45] = 0x00 // Terminator

	binary.BigEndian.PutUint16(packet[46:48], 0x0021) // Type NBSTAT
	binary.BigEndian.PutUint16(packet[48:50], 0x0001) // Class IN

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	if n < 56 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	// Parse NetBIOS Node Status response
	// Find Answer RRs (bytes 6-8)
	ansRRs := binary.BigEndian.Uint16(buf[6:8])
	if ansRRs < 1 {
		return nil, fmt.Errorf("no answer records in NetBIOS response")
	}

	// Skip question name (at byte 12)
	offset := 12
	for offset < n && buf[offset] != 0 {
		offset += int(buf[offset]) + 1
	}
	offset += 5 // Skip terminator (1) + Type (2) + Class (2)

	// Now at Answer RR: Name (variable or ptr), Type (2), Class (2), TTL (4), DataLength (2)
	if offset+10 > n {
		return nil, fmt.Errorf("truncated response before RR data")
	}

	// Skip RR name
	if buf[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		for offset < n && buf[offset] != 0 {
			offset += int(buf[offset]) + 1
		}
		offset++
	}

	offset += 8 // Skip Type (2), Class (2), TTL (4)
	if offset+2 > n {
		return nil, fmt.Errorf("truncated response before data length")
	}

	rdLength := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2

	if offset+rdLength > n || rdLength < 1 {
		return nil, fmt.Errorf("invalid data length")
	}

	numNames := int(buf[offset])
	offset++

	info := &NetBIOSInfo{}

	for i := 0; i < numNames && offset+18 <= n; i++ {
		nameBytes := buf[offset : offset+15]
		typeByte := buf[offset+15]
		flags := binary.BigEndian.Uint16(buf[offset+16 : offset+18])
		offset += 18

		name := strings.TrimSpace(string(nameBytes))
		isGroup := (flags & 0x8000) != 0

		switch typeByte {
		case 0x00:
			if isGroup {
				if info.Workgroup == "" {
					info.Workgroup = name
				}
			} else {
				if info.ComputerName == "" {
					info.ComputerName = name
				}
			}
		case 0x20:
			if !isGroup && info.ComputerName == "" {
				info.ComputerName = name
			}
		case 0x03:
			if !isGroup && info.UserName == "" {
				info.UserName = name
			}
		}
	}

	// MAC address is at the end of node status data (6 bytes)
	if offset+6 <= n {
		mac := net.HardwareAddr(buf[offset : offset+6])
		info.MAC = mac.String()
	}

	return info, nil
}
