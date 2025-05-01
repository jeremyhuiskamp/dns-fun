package dns_test

import (
	"dns"
	"slices"
	"strings"
	"testing"
)

func TestParseValidNames(t *testing.T) {
	for _, test := range []struct {
		in  string
		out dns.Name
	}{
		{"google.com", name("google", "com")},
		{"google.com.", name("google", "com")},
		{"", name()},
		{
			strings.Repeat("1234567890", 6) + "123.com",
			name(dns.Label(strings.Repeat("1234567890", 6)+"123"), "com"),
		},
		{
			// 255 bytes = 127 parts, plus 1 byte for root:
			strings.Repeat("a.", 127),
			slices.Repeat(name("a"), 127),
		},
	} {
		t.Run(test.in, func(t *testing.T) {
			got, err := dns.ParseName(test.in)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, test.out) {
				t.Fatalf("expected %q, got %q", test.out, got)
			}
		})
	}
}

func TestParseInvalidNames(t *testing.T) {
	for _, test := range []struct {
		in  string
		err error
	}{
		{".google.com", dns.ErrEmtyLabel},
		{
			strings.Repeat("1234567890", 6) + "1234.com",
			dns.ErrLabelTooLong,
		},
		{
			// 126 * 2 + 3 =
			strings.Repeat("a.", 126) + "aa",
			dns.ErrNameTooLong,
		},
		// TODO: check length with non-ascii characters
	} {
		t.Run(test.in, func(t *testing.T) {
			_, err := dns.ParseName(test.in)
			if err != test.err {
				t.Fatalf("expected err %q but got %q", test.err, err)
			}
		})
	}
}

func TestNameEqual(t *testing.T) {
	if !name("google", "com").Equal(name("google", "com")) {
		t.Error("identical names should be equal")
	}

	if !name("GOOGLE", "com").Equal(name("google", "com")) {
		t.Error("names varying only in case should be equal")
	}

	if name("google", "com").Equal(name("apple", "com")) {
		t.Error("different names should be different")
	}

	if name("google", "co").Equal(name("google", "co", "uk")) {
		t.Error("a prefix should be different")
	}

	if name("co", "uk").Equal(name("google", "co", "uk")) {
		t.Error("a suffix should be different")
	}
}

func TestNameIsParent_IsSubdomain(t *testing.T) {
	co_uk := name("co", "uk")
	google_co_uk := name("google", "co", "uk")

	if !co_uk.IsParentOf(google_co_uk) {
		t.Errorf("expected %q to be parent of %q", co_uk, google_co_uk)
	}

	co_UK := name("co", "UK")
	if !co_UK.IsParentOf(google_co_uk) {
		t.Errorf("expected %q to be parent of %q", co_UK, google_co_uk)
	}

	if google_co_uk.IsParentOf(co_uk) {
		t.Errorf("%q should not be parent of %q", google_co_uk, co_uk)
	}

	if co_uk.IsParentOf(co_uk) {
		t.Errorf("%q should not be parent of self", co_uk)
	}

	if !google_co_uk.IsSubdomainOf(co_uk) {
		t.Errorf("expected %q to be subdomain of %q", google_co_uk, co_uk)
	}

	if co_uk.IsSubdomainOf(google_co_uk) {
		t.Errorf("%q should not be subdomain of %q", co_uk, google_co_uk)
	}

	if co_uk.IsSubdomainOf(co_uk) {
		t.Errorf("%q should not be subdomain of self", co_uk)
	}
}
