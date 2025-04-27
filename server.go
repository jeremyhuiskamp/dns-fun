package dns

import (
	"fmt"
	"net"
	"time"
)

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

// Listen is a harness for interactive testing. I test it with
// command-line tools like `host` and change it over time to
// explore various capabilities.
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
		msg, err := ParseDNSMessage(buffer[:n])
		if err != nil {
			fmt.Printf("couldn't parse message: %s\n", err)
			continue
		}

		fmt.Printf("%s\n", msg.String())
		rsp := MakeResponse(msg)
		for _, question := range msg.Questions {
			if question.Type == A {
				answer := Answer{
					Names:        question.Names,
					Class:        question.Class,
					Type:         question.Type,
					TTL:          120 * time.Second,
					ResourceData: net.ParseIP("1.2.3.4"),
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
