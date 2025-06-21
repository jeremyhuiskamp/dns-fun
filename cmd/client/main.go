package main

import (
	"dns"
	"dns/resolve"
	"fmt"
	"log"
	"os"
)

func main() {
	for _, name := range os.Args[1:] {
		fmt.Printf("resolving %q\n", name)
		host, err := dns.ParseName(name)
		if err != nil {
			log.Printf("skipping invalid name %q: %s\n", name, err)
			continue
		}
		rsp, err := resolve.Resolve(dns.Question{
			Name:  host,
			Type:  dns.A,
			Class: dns.IN,
		})
		if err != nil {
			log.Printf("WARN: unable to query: %s", err)
			continue
		}

		fmt.Printf("%d Answers:\n", len(rsp.Answers))
		for _, answer := range rsp.Answers {
			printResource(answer)
		}

		if len(rsp.Answers) < 1 { // fallback info, in case we didn't get an answer...
			fmt.Printf("%d Authorities RRs:\n", len(rsp.Authorities))
			for _, authority := range rsp.Authorities {
				printResource(authority)
			}
			fmt.Printf("%d Additional RRs:\n", len(rsp.Additional))
			for _, additional := range rsp.Additional {
				printResource(additional)
			}
		}
	}
}

func printResource(r dns.Resource) {
	fmt.Printf("  name: %s\n", r.Name)
	fmt.Printf("    type: %s\n", r.Type)
	fmt.Printf("    ttl: %s\n", r.TTL)
	fmt.Printf("    data: %s\n", r.Data)
}
