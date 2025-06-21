package main

import (
	"dns"
	"dns/resolve"
	"fmt"
	"log"
	"net"
)

func main() {
	srv, err := NewServer(53)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	if err := srv.Listen(); err != nil {
		log.Fatalf("Failed to start UDP listener: %v", err)
	}
}

type Server struct {
	addr *net.UDPAddr
}

func NewServer(port int) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	return &Server{addr: addr}, nil
}

func (s *Server) Listen() error {
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Printf("Listening for UDP packets on port %d\n", s.addr.Port)

	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		fmt.Printf("Received %d bytes from %s\n", n, addr.String())
		msg, err := dns.ParseMessage(buffer[:n])
		if err != nil {
			fmt.Printf("couldn't parse message: %s\n", err)
			continue
		}

		go handle(msg, conn, addr)
	}
}

func handle(qry dns.Message, conn *net.UDPConn, rspAddr *net.UDPAddr) {
	fmt.Printf("%s\n", qry.String())

	rsp := dns.MakeResponse(qry)
	for _, question := range qry.Questions {
		if question.Type == dns.A {
			resolved, err := resolve.Resolve(question.Name)
			if err != nil {
				fmt.Printf("couldn't resolve %q: %s\n", question.Name, err)
			} else {
				rsp.Answers = append(rsp.Answers, resolved.Answers...)
				rsp.Authorities = append(rsp.Authorities, resolved.Authorities...)
				rsp.Additional = append(rsp.Additional, resolved.Additional...)
			}
			continue
		}
	}

	rspBuf := make([]byte, 0, 1024)
	rspBuf, err := rsp.WriteTo(rspBuf)
	if err != nil {
		fmt.Printf("failed to write response: %s\n", err)
		return
	}

	_, err = conn.WriteToUDP(rspBuf, rspAddr)
	if err != nil {
		fmt.Printf("failed to send response to %s: %s", rspAddr.String(), err)
	}
}
