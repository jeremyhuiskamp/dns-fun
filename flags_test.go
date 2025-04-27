package dns_test

import (
	"dns"
	"testing"
)

func TestFlagSetting(t *testing.T) {
	fOrig := dns.Flags(0)
	if fOrig.Type() != dns.Query {
		t.Errorf("expected type Query by default, got %s",
			fOrig.Type())
	}

	fRsp := fOrig.WithType(dns.Response)
	if fRsp.Type() != dns.Response {
		t.Errorf("expected type Response, got %s",
			fRsp.Type())
	}

	fQry := fRsp.WithType(dns.Query)
	if fQry.Type() != dns.Query {
		t.Errorf("expected type Query again, got %s",
			fQry.Type())
	}

	if fQry != fOrig {
		t.Errorf("all other fields should remain unchanged, exp %#b, got %#b",
			fOrig, fQry)
	}
}
