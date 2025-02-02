package icmp

import (
	"flag"
	"log"
	"net"
)

var (
	ip       string
	addrtype string
)

func initFlags() {
	flag.StringVar(&ip, "ip", "8.8.8.8", "IP address to send ICMP packet")
	flag.StringVar(&addrtype, "addrtype", "ipv4", "Address type (ipv4 or ipv6)")

	flag.Parse()
}

// Ping pings the provided ip address via flag (-ip) with the address type (-addrtype)
func Ping() {
	initFlags()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Fatalf("Invalid IP address: %s", ip)
		return
	}

	var ipBytes net.IP

	switch addrtype {
	case "ipv4":
		ipBytes = parsedIP.To4()
		if ipBytes == nil {
			log.Fatalf("Invalid IP address: %s", ip)
		}

	case "ipv6":
		ipBytes = parsedIP.To16()
		if ipBytes == nil {
			log.Fatalf("Invalid IP address: %s", ip)
		}

	default:
		log.Fatalf("Invalid address type: %s", addrtype)
	}

	ping(ipBytes, addrtype)
}
