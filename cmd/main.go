package main

import (
	"dns"
	"log"
)

func main() {
	srv, err := dns.NewServer(53)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	if err := srv.Listen(); err != nil {
		log.Fatalf("Failed to start UDP listener: %v", err)
	}
}
