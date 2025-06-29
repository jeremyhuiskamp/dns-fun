package resolve

import (
	"dns"
	"errors"
	"fmt"
	"net"
	"slices"
)

var ripeRootIP = net.ParseIP("193.0.14.129")

// Resolve is a very rudimentary iterative resolver.  Only for testing
// purposes; it has many weaknesses.
func Resolve(question dns.Question) (dns.Message, error) {
	return resolve(ripeRootIP, question)
}

func resolve(serverIP net.IP, question dns.Question) (dns.Message, error) {
	rsp, err := query(serverIP, question)
	if err != nil {
		return dns.Message{}, err
	}

	answers := findAnswers(question.Name, rsp)
	for _, answer := range answers {
		if answer.Type == question.Type {
			// TODO: put this check up in findAnswers
			return rsp, nil
		}

		// hmm, I bet you can maliciously have CNAMEs pointing at each other?
		if cname, ok := answer.Data.(dns.Name); ok && answer.Type == dns.CNAME {
			rsp, err := resolve(ripeRootIP, dns.Question{
				Name:  cname,
				Type:  question.Type,
				Class: question.Class,
			})
			if err != nil {
				return dns.Message{}, err
			}
			// typically servers will return the cname record first
			// so we should probably do that too?
			rsp.Answers = append(rsp.Answers, answer)
			return rsp, nil
		}
	}

	nextServerName, nextServerIP := findAnAuthoritativeServer(rsp)
	if nextServerIP != nil {
		// a malicious server could also send us into infinite recursion here...
		return resolve(nextServerIP, question)
	}

	if nextServerName != nil {
		rsp, err := resolve(ripeRootIP, dns.Question{
			Name:  nextServerName,
			Type:  dns.A, // should try AAAA?
			Class: dns.IN,
		})
		if err != nil {
			return dns.Message{}, err
		}
		answers := findAnswers(nextServerName, rsp)
		for _, answer := range answers {
			if ip, ok := answer.Data.(net.IP); ok && answer.Type == dns.A {
				return resolve(ip, question)
			}
		}
	}

	return rsp, errors.New("could not find authoritative server")
}

// TODO: multiple questions?
// Eg, A and AAAA records
func query(serverIP net.IP, question dns.Question) (dns.Message, error) {
	// idea for a test framework:
	// - instrument this to capture each query/response and write it to json
	// - replace this with a dummy that returns data from the json

	query := dns.Message{
		ID:        123, // TODO: better id!!!
		Flags:     dns.Flags(0).WithType(dns.Query),
		Questions: []dns.Question{question},
	}

	buf, err := query.WriteTo(nil)
	if err != nil {
		return dns.Message{}, fmt.Errorf("couldn't serialize query: %s", err)
	}

	serverAddr := &net.UDPAddr{
		IP:   serverIP,
		Port: 53,
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return dns.Message{}, fmt.Errorf("couldn't dial root server: %s", err)
	}

	n, err := conn.Write(buf)
	if err != nil {
		return dns.Message{}, fmt.Errorf("unable to write udp message: %s", err)
	} else if n < len(buf) {
		return dns.Message{}, fmt.Errorf("wrote only %d bytes of %d byte message", n, len(buf))
	}

	rspBuf := make([]byte, 1024)
	n, err = conn.Read(rspBuf)
	if err != nil {
		return dns.Message{}, fmt.Errorf("couldn't read udp message: %s", err)
	}

	// TODO: validate the msg ID
	return dns.ParseMessage(rspBuf[:n])
}

func findAnswers(name dns.Name, rsp dns.Message) []dns.Resource {
	var answers []dns.Resource
	for _, answer := range rsp.Answers {
		// aside from malicious responses, is there a reason that we'd get
		// non-matching answers in a response?
		if slices.Equal(answer.Name, name) {
			answers = append(answers, answer)
		}
	}
	return answers
}

func findAnAuthoritativeServer(rsp dns.Message) (dns.Name, net.IP) {
	for _, authority := range rsp.Authorities {
		if authority.Type != dns.NS {
			continue
		}

		authorityName, ok := authority.Data.(dns.Name)
		if !ok {
			continue
		}

		// TODO: make sure that the authority is an authority for the domain
		// or some parent zone of our actual target.
		// But is there any reason, aside from malicious responses, that we'd
		// get unrelated authorities here?

		for _, additional := range rsp.Additional {
			// TODO: support AAAA as well
			// For now we probably need to prefer A at least, since I don't have
			// a v6 address to test from!
			if additional.Type != dns.A {
				continue
			}

			if !slices.Equal(authorityName, additional.Name) {
				continue
			}

			if ip, ok := additional.Data.(net.IP); ok {
				fmt.Printf("..authority: %s, %s, %s\n",
					authority.Name, authorityName, ip)
				return authorityName, ip
			}
		}
		// Oh, we might get an authority with no ip address in it!
		// Eg, the "de" authoritative servers know that ns1.google.com is
		// an authority for google.de, but they don't know the ip address
		// of ns1.google.com because it's in a different zone!
		fmt.Printf("..authority: %s, %s, ??\n", authority.Name, authorityName)
		return authorityName, nil
	}
	return nil, nil
}
