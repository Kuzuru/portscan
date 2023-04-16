package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	timeout = 10 * time.Second
)

func main() {
	parser := argparse.NewParser("portscan", "TCP and UDP port scanner")
	mode := parser.Selector("t", "type", []string{"-t", "-u"}, &argparse.Options{
		Required: true,
		Help:     "Scan mode (-t for TCP, -u for UDP)",
	})
	portRange := parser.String("p", "ports", &argparse.Options{
		Required: true,
		Help:     "Port range (N1-N2)",
	})
	host := parser.String("", "host", &argparse.Options{
		Required: true,
		Help:     "Host address",
	})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	rangeVals := strings.Split(*portRange, "-")
	start, _ := strconv.Atoi(rangeVals[0])
	end, _ := strconv.Atoi(rangeVals[1])

	if *mode == "-t" {
		scanTCP(*host, start, end)
	} else if *mode == "-u" {
		scanUDP(*host, start, end)
	}
}

func scanTCP(host string, start, end int) {
	var wg sync.WaitGroup
	for port := start; port <= end; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				defer conn.Close()
				protocol := getProtocol("TCP", p)
				fmt.Printf("TCP %d %s\n", p, protocol)
			}
		}(port)
	}
	wg.Wait()
}

func scanUDP(host string, start, end int) {
	var wg sync.WaitGroup
	for port := start; port <= end; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("udp", address, timeout)
			if err == nil {
				defer conn.Close()
				protocol := getProtocol("UDP", p)
				fmt.Printf("UDP %d %s\n", p, protocol)
			}
		}(port)
	}
	wg.Wait()
}

func getProtocol(proto string, port int) string {
	protocols := map[string]map[int]string{
		"TCP": {
			80:   "HTTP",
			443:  "HTTPS",
			25:   "SMTP",
			110:  "POP3",
			143:  "IMAP",
			53:   "DNS",
			123:  "NTP",
			20:   "FTP",
			21:   "FTP",
			22:   "SSH",
			23:   "Telnet",
			465:  "SMTPS",
			587:  "SMTP",
			993:  "IMAPS",
			995:  "POP3S",
			3306: "MySQL",
			3389: "RDP",
			5432: "PostgreSQL",
		},
		"UDP": {
			53:   "DNS",
			123:  "NTP",
			67:   "DHCP",
			68:   "DHCP",
			69:   "TFTP",
			161:  "SNMP",
			162:  "SNMP",
			137:  "NetBIOS",
			138:  "NetBIOS",
			139:  "NetBIOS",
			389:  "LDAP",
			1701: "L2TP",
			500:  "IKE",
			1812: "RADIUS",
			1813: "RADIUS",
			1900: "SSDP",
		},
	}

	if proto == "TCP" {
		if val, ok := protocols["TCP"][port]; ok {
			return val
		}
	} else if proto == "UDP" {
		if val, ok := protocols["UDP"][port]; ok {
			return val
		}
	}

	return ""
}
