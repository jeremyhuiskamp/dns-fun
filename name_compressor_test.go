package dns_test

import (
	"dns"
	"slices"
	"testing"
)

func TestLookupUnknownName(t *testing.T) {
	nc := dns.NewNameCompressor()
	tryCompress(t, nc, 20, name("foo", "com"), 0, "foo", "com")
}

func TestBasicNameCompression(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("foo", "com"))

	tryCompress(t, nc, 20, name("foo", "com"), 5)
}

func TestReferenceLongerName(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("foo", "bar", "com"))

	// 9 = 5 + len("foo") + 1
	tryCompress(t, nc, 20, name("bar", "com"), 9)
}

func TestReferenceShorterName(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("bar", "com"))

	tryCompress(t, nc, 20, name("foo", "bar", "com"), 5, "foo")
}

func TestReferenceNameWithSharedParent(t *testing.T) {
	nc := dns.NewNameCompressor()
	nc.Compress(5, name("qux", "bar", "com"))

	tryCompress(t, nc, 20, name("foo", "bar", "com"), 9, "foo")
}

func tryCompress(
	t *testing.T,
	nc dns.NameCompressor,
	offset uint16,
	name dns.Name,
	expPointer uint16,
	expPrefix ...dns.Label,
) {
	t.Helper()
	gotPrefix, gotPointer := nc.Compress(offset, name)
	if gotPointer != expPointer {
		t.Errorf("expected pointer %d but got %d", expPointer, gotPointer)
	}
	if !slices.Equal(gotPrefix, expPrefix) {
		t.Errorf("expected prefix %q but got %q", expPrefix, gotPrefix)
	}
}
