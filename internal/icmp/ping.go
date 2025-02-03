package icmp

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
)

type Response struct {
	IP                 string  `json:"ip"`
	RTT                float64 `json:"rtt"`
	Addr               string  `json:"addr"`
	TTL                int     `json:"ttl"`
	ICMPType           int     `json:"icmp_type"`
	ICMPCode           int     `json:"icmp_code"`
	ICMPIdentifier     int     `json:"icmp_identifier"`
	ICMPSequenceNumber int     `json:"icmp_sequence_number"`
}

func ping(ipBytes net.IP, addrtype string) {
	// Code for sending ICMP packet to an IPv4 address

	var socket int
	var destAddr syscall.Sockaddr
	if addrtype == "ipv4" {
		socket, destAddr = createIPv4Socket(ipBytes)
	} else {
		socket, destAddr = createIPv6Socket(ipBytes)
	}

	// ref: https://www.geeksforgeeks.org/internet-control-message-protocol-icmp/
	icmpPacket := []byte{
		8, 0, 0, 0, // (8=echo request, 0=code, 0=checksum)
		0, 1, 0, 1, // (0,1 = indentifier, 0,1=sequence number)
		'o', 'k',
	}

	checksum := calculateCheckSum(icmpPacket)
	icmpPacket[2] = byte(checksum >> 8)
	icmpPacket[3] = byte(checksum & 0xFF)

	startTime := time.Now()

	err := syscall.Sendto(socket, icmpPacket, 0, destAddr)
	if err != nil {
		log.Fatalf("Error sending packet: %v", err)
	}

	log.Println("ICMP packet sent successfully")

	var buf [512]byte
	_, _, err = syscall.Recvfrom(socket, buf[:], 0)
	if err != nil {
		log.Fatalf("Error receiving packet: %v", err)
	}

	endTime := time.Now()

	elapsed := endTime.Sub(startTime)

	log.Println("ICMP packet received successfully")

	ttl := int(buf[8])

	icmpType := int(buf[20])
	icmpCode := int(buf[21])
	icmpIdentifier := int(buf[24])<<8 + int(buf[25])
	icmpSequenceNumber := int(buf[26])<<8 + int(buf[27])

	response := Response{
		IP:                 ipBytes.String(),
		RTT:                float64(elapsed.Microseconds()) / 1000.0,
		Addr:               addrtype,
		TTL:                ttl,
		ICMPType:           icmpType,
		ICMPCode:           icmpCode,
		ICMPIdentifier:     icmpIdentifier,
		ICMPSequenceNumber: icmpSequenceNumber,
	}

	jsonResponse, err := json.MarshalIndent(response, "", " ")
	if err != nil {
		log.Fatalf("Error marshalling response: %v", err)
	}

	fmt.Println(string(jsonResponse))
}

func createIPv4Socket(ipBytes net.IP) (int, *syscall.SockaddrInet4) {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		log.Fatalf("Error creating socket: %v", err)
		return -1, &syscall.SockaddrInet4{}
	}

	destAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]},
	}

	return socket, destAddr
}

func createIPv6Socket(ip net.IP) (int, *syscall.SockaddrInet6) {
	socket, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		log.Fatalf("Error creating IPv6 socket: %v", err)
	}

	var destAddr syscall.SockaddrInet6
	copy(destAddr.Addr[:], ip[0:16])
	destAddr.Port = 0

	return socket, &destAddr
}

func calculateCheckSum(data []byte) uint16 {
	sum := 0
	for i := 0; i < len(data)-1; i += 2 {
		sum += int(data[i])<<8 + int(data[i+1])
		// upper 8 bits   //lower 8 bits
	}

	if len(data)%2 == 1 {
		sum += int(data[len(data)-1]) << 8 // treat as upper 8 bit
	}

	if sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}
