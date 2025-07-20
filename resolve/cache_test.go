package resolve_test

import (
	"dns"
	"dns/resolve"
	"net"
	"reflect"
	"testing"
)

func TestCacheHit(t *testing.T) {
	c := resolve.NewCache()
	q := dns.Question{
		Name:  dns.Name{"foo", "bar"},
		Type:  dns.A,
		Class: dns.IN,
	}
	r := dns.Resource{
		Name:  dns.Name{"foo", "bar"},
		Type:  dns.A,
		Class: dns.IN,
		TTL:   10,
		Data:  net.ParseIP("192.168.0.1"),
	}
	c.Put(q, []dns.Resource{r})
	gotR, ok := c.Get(q)
	if !ok {
		t.Fatal("cached record not found")
	}
	if !reflect.DeepEqual([]dns.Resource{r}, gotR) {
		t.Fatalf("expected record:\n%#v\ngot record:\n%#v",
			r, gotR)
	}
}
