package main

import (
	"bytes"
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
		msg, err := dns.ParseMessage(buffer[:n])
		if err != nil {
			fmt.Printf("couldn't parse message: %s\n", err)
			continue
		}

		go handle(msg, conn, addr)
	}
}

func handle(qry dns.Message, conn *net.UDPConn, rspAddr *net.UDPAddr) {
	rsp := dns.MakeResponse(qry)
	// TODO: reject queries with more than one question
	for _, question := range qry.Questions {
		resolved, err := resolve.Resolve(question)
		if err != nil {
			fmt.Printf("couldn't resolve %q/%s: %s\n",
				question.Name, question.Type, err)
		} else {
			// TODO: inspect resolved msg header for reply codes
			logRsp(question, resolved)
			rsp.Answers = append(rsp.Answers, resolved.Answers...)
			rsp.Authorities = append(rsp.Authorities, resolved.Authorities...)
			rsp.Additional = append(rsp.Additional, resolved.Additional...)
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

func logRsp(question dns.Question, rsp dns.Message) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s/%s? -> ", question.Name, question.Type)
	for _, answer := range rsp.Answers {
		fmt.Fprintf(&buf, "%s=(%s), ", answer.Name, answer.Data)
	}
	fmt.Println(buf.String())
}
