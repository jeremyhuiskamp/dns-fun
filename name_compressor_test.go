package dns_test

import (
	"dns"
	"testing"
)

func TestBasicNameCompression(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Record(5, name("foo", "com"))
	skip, offset := nc.Lookup(name("foo", "com"))
	if skip != 0 {
		t.Errorf("expected not to skip any prefixes, but got %d", skip)
	}
	if offset != 5 {
		t.Errorf("expected to find back offset 5, but got %d", offset)
	}
}

func TestReferenceLongerName(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Record(5, name("foo", "bar", "com"))

	skip, offset := nc.Lookup(name("bar", "com"))
	if offset != 9 { // 5 + len("foo") + 1
		t.Errorf("expected offset 9, but got %d", offset)
	}

	if skip != 0 {
		t.Errorf("expected not to skip any prefixes, but got %d", skip)
	}
}

func TestReferenceShorterName(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Record(5, name("bar", "com"))

	skip, offset := nc.Lookup(name("foo", "bar", "com"))
	if offset != 5 {
		t.Errorf("expected offset 5, but got %d", offset)
	}

	if skip != 1 {
		t.Errorf("expected to skip one prefix, but got %d", skip)
	}
}

func TestReferenceNameWithSharedParent(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Record(5, name("qux", "bar", "com"))

	skip, offset := nc.Lookup(name("foo", "bar", "com"))
	if offset != 9 { // start of "bar"
		t.Errorf("expected offset 9, but got %d", offset)
	}

	if skip != 1 {
		t.Errorf("expected to skip one prefix, but got %d", skip)
	}
}

func TestLookupUnknownName(t *testing.T) {
	nc := dns.NewNameCompressor()
	// skip is irrelevant if no offset is found
	_, offset := nc.Lookup(name("foo", "com"))
	if offset != 0 {
		t.Errorf("expected to find no offset, but got %d", offset)
	}
}
