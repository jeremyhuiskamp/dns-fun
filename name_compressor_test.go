package dns_test

import (
	"dns"
	"slices"
	"testing"
)

func TestBasicNameCompression(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("foo", "com"))
	prefix, offset := nc.Compress(20, name("foo", "com"))
	if len(prefix) != 0 {
		t.Errorf("expected no prefix, but got %q", prefix)
	}
	if offset != 5 {
		t.Errorf("expected to find back offset 5, but got %d", offset)
	}
}

func TestReferenceLongerName(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("foo", "bar", "com"))

	prefix, offset := nc.Compress(20, name("bar", "com"))
	if offset != 9 { // 5 + len("foo") + 1
		t.Errorf("expected offset 9, but got %d", offset)
	}

	if len(prefix) != 0 {
		t.Errorf("expected to skip all prefixes, but got %q", prefix)
	}
}

func TestReferenceShorterName(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("bar", "com"))

	prefix, offset := nc.Compress(20, name("foo", "bar", "com"))
	if offset != 5 {
		t.Errorf("expected offset 5, but got %d", offset)
	}

	if exp := name("foo"); !slices.Equal(prefix, exp) {
		t.Errorf("expected prefix %q, but got %q", exp, prefix)
	}
}

func TestReferenceNameWithSharedParent(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("qux", "bar", "com"))

	prefix, offset := nc.Compress(20, name("foo", "bar", "com"))
	if offset != 9 { // start of "bar"
		t.Errorf("expected offset 9, but got %d", offset)
	}

	if exp := name("foo"); !slices.Equal(prefix, exp) {
		t.Errorf("expected prefix %q, but got %q", exp, prefix)
	}
}

func TestLookupUnknownName(t *testing.T) {
	nc := dns.NewNameCompressor()
	prefix, offset := nc.Compress(20, name("foo", "com"))
	if offset != 0 {
		t.Errorf("expected to find no offset, but got %d", offset)
	}
	if exp := name("foo", "com"); !slices.Equal(exp, prefix) {
		t.Errorf("expected prefix %q, but got %q", exp, prefix)
	}
}
