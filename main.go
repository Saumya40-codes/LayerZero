package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"syscall"
)

var ip string

func main() {
	flag.StringVar(&ip, "ip", "8.8.8.8", "IP address to send ICMP packet")
	flag.Parse()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Fatalf("Invalid IP address: %s", ip)
		return
	}

	ipBytes := parsedIP.To4()
	if ipBytes == nil {
		log.Fatalf("Invalid IP address: %s", ip)
		return
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Println("Error creating socket")
		return
	}

	defer syscall.Close(socket)

	destAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]},
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

	err = syscall.Sendto(socket, icmpPacket, 0, destAddr)
	if err != nil {
		log.Fatalf("Error sending packet: %v", err)
	}

	log.Println("ICMP packet sent successfully")
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
