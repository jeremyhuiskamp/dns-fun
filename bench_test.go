package dns_test

import (
	"dns"
	"testing"
)

func BenchmarkParseLargeMessage(b *testing.B) {
	for b.Loop() {
		_, err := dns.ParseMessage(googleRootAResponse)
		if err != nil {
			b.Errorf("unexpected parsing error: %s", err)
		}
	}
}

func BenchmarkParseSmallMessage(b *testing.B) {
	for b.Loop() {
		_, err := dns.ParseMessage(googleQuery)
		if err != nil {
			b.Errorf("unexpected parsing error: %s", err)
		}
	}
}

func BenchmarkWriteSmallMessage(b *testing.B) {
	msg, err := dns.ParseMessage(googleQuery)
	if err != nil {
		b.Errorf("unexpected parsing error: %s", err)
	}
	buf := make([]byte, 0, 1024)
	for b.Loop() {
		_, err := msg.WriteTo(buf)
		if err != nil {
			b.Errorf("unexpected writing error: %s", err)
		}
	}
}

func BenchmarkWriteLargeMessage(b *testing.B) {
	msg, err := dns.ParseMessage(googleRootAResponse)
	if err != nil {
		b.Errorf("unexpected parsing error: %s", err)
	}
	buf := make([]byte, 0, 1024)
	for b.Loop() {
		_, err := msg.WriteTo(buf)
		if err != nil {
			b.Errorf("unexpected writing error: %s", err)
		}
	}
}
