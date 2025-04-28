package dns_test

import (
	"dns"
	"io"
	"testing"
)

func FuzzParseDNSMessage(f *testing.F) {
	f.Add(googleQuery)
	f.Add(googleResponse)
	f.Add(googleAAAAResponse)
	f.Add(googleMXResponse)
	f.Add(googleRootAResponse)
	f.Add(cnameWithMultipleAnswers)
	f.Fuzz(func(t *testing.T, buf []byte) {
		_, err := dns.ParseDNSMessage(buf)
		if !isExpectedParseError(err) {
			t.Errorf("unexpected error while parsing: %s", err)
		}

		// TODO: consider writing the message too
		// Perhaps some invalid input could mess up the writer?
	})
}

func isExpectedParseError(err error) bool {
	return err == nil ||
		err == io.ErrShortBuffer ||
		err == dns.ErrInvalidCompression
}
