package main

import (
	"dns"
	"fmt"
	"log"
	"net"
)

func main() {
	question := dns.Question{
		Name:  dns.Name{"google", "com"},
		Type:  dns.A,
		Class: dns.IN,
	}

	query := dns.Message{
		ID:        123,
		Flags:     dns.Flags(0).WithType(dns.Query),
		Questions: []dns.Question{question},
	}

	buf, err := query.WriteTo(nil)
	if err != nil {
		log.Fatalf("couldn't serialize query: %s\n", err)
	}

	root := &net.UDPAddr{
		IP:   net.ParseIP("198.41.0.4"),
		Port: 53,
	}

	conn, err := net.DialUDP("udp", nil, root)
	if err != nil {
		log.Fatalf("couldn't dial root server: %s\n", err)
	}

	n, err := conn.Write(buf)
	if err != nil {
		log.Fatalf("unable to write udp message: %s\n", err)
	} else if n < len(buf) {
		log.Printf("WARN: wrote only %d bytes of %d byte message\n", n, len(buf))
	}

	rspBuf := make([]byte, 1024)
	n, err = conn.Read(rspBuf)
	if err != nil {
		log.Fatalf("couldn't read udp message: %s\n", err)
	}

	rsp, err := dns.ParseMessage(rspBuf[:n])
	if err != nil {
		log.Fatalf("couldn't parse response: %s\n", err)
	}

	fmt.Printf("%d Answers:\n", len(rsp.Answers))
	for _, answer := range rsp.Answers {
		printResource(answer)
	}
	fmt.Printf("%d Authorities RRs:\n", len(rsp.Authorities))
	for _, authority := range rsp.Authorities {
		printResource(authority)
	}
	fmt.Printf("%d Additional RRs:\n", len(rsp.Additional))
	for _, additional := range rsp.Additional {
		printResource(additional)
	}
}

func printResource(r dns.Resource) {
	fmt.Printf("  name: %s\n", r.Name)
	fmt.Printf("    type: %s\n", r.Type)
	fmt.Printf("    ttl: %s\n", r.TTL)
	fmt.Printf("    data: %s\n", r.Data)
}
