package main

import (
	"dns"
	"dns/resolve"
	"fmt"
	"log"
	"net"
	"time"
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
		fmt.Printf("Received %d bytes from %s: %s\n", n, addr.String(), string(buffer[:n]))
		msg, err := dns.ParseMessage(buffer[:n])
		if err != nil {
			fmt.Printf("couldn't parse message: %s\n", err)
			continue
		}

		fmt.Printf("%s\n", msg.String())
		rsp := dns.MakeResponse(msg)
		for _, question := range msg.Questions {
			answer := dns.Resource{
				Name:  question.Name,
				Class: question.Class,
				Type:  question.Type,
				TTL:   120 * time.Second,
			}
			if question.Type == dns.A {
				resolved, err := resolve.Resolve(question.Name)
				if err != nil {
					fmt.Printf("couldn't resolve %q: %s\n", question.Name, err)
					// now what???
				} else {
					rsp.Answers = append(rsp.Answers, resolved.Answers...)
					rsp.Authorities = append(rsp.Authorities, resolved.Authorities...)
					rsp.Additional = append(rsp.Additional, resolved.Additional...)
				}
			} else if question.Type == dns.AAAA {
				answer.Data = net.ParseIP("1.2.3.4")
				rsp.Answers = append(rsp.Answers, answer)
			} else if question.Type == dns.MX {
				answer.Data = dns.MXRecord{
					Preference: 10,
					MailExchange: dns.Name([]dns.Label{
						"smtp",
						"test",
						"com",
					}),
				}
				rsp.Answers = append(rsp.Answers, answer)
			}
		}
		rspBuf := buffer[:0]
		rspBuf, err = rsp.WriteTo(rspBuf)
		if err != nil {
			fmt.Printf("failed to write response: %s\n", err)
			continue
		}

		_, err = conn.WriteToUDP(rspBuf, addr)
		if err != nil {
			fmt.Printf("failed to send response to %s: %s", addr.String(), err)
		}
	}
}
