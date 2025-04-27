package dns_test

import (
	"dns"
	"fmt"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"
)

// Message types to add tests for:
// - anything with a AAAA record
// - NS records

// generated with `host google.com`
var googleQuery = []byte{
	0xc2, 0x1b, // 0,  id
	0x01, 0x00, // 2,  flags
	0x00, 0x01, // 4,  number of questions
	0x00, 0x00, // 6,  number of answers
	0x00, 0x00, // 8,  number of authority RRs
	0x00, 0x00, // 10, number of additional RRs
	0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // 12, "google"
	0x03, 0x63, 0x6f, 0x6d, // 19, "com"
	0x00,       // 23, end name
	0x00, 0x01, // 24, query type A
	0x00, 0x01, // 26, query class IN
}

// TODO: need a test with all flags set to different
// values.

func TestParseQuery(t *testing.T) {
	q, err := dns.ParseDNSMessage(googleQuery)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}
	if got := q.ID; got != 0xc21b {
		t.Errorf("expected id 0xc21b, got %x", q.ID)
	}

	flags := q.Flags
	if got := flags.Type(); got != dns.Query {
		t.Errorf("expected type Query, got %s", got)
	}
	if got := flags.OpCode(); got != dns.StandardQuery {
		t.Errorf("expected op code StandardQuery, got %s", got)
	}
	if got := flags.Authoritative(); got != false {
		t.Errorf("expected not authoritative, got %t", got)
	}
	if got := flags.Truncated(); got != false {
		t.Errorf("expected not truncated, got %t", got)
	}
	if got := flags.RecursionDesired(); got != true {
		t.Errorf("expected recursion desired, got %t", got)
	}
	if got := flags.RecursionAvailable(); got != false {
		t.Errorf("expected not recursion available, got %t", got)
	}
	if got := flags.ResponseCode(); got != dns.NoError {
		t.Errorf("expected no error, got %s", got)
	}

	questions := q.Questions
	if count := len(questions); count != 1 {
		t.Errorf("expected 1 question, got %d", count)
	} else {
		question := questions[0]
		if !slices.Equal(question.Names, []string{
			"google", "com",
		}) {
			t.Errorf("expected query for google.com, got %q",
				question.Names)
		}

		if got := question.Type; got != dns.A {
			t.Errorf("expected query type A, got %s", got)
		}

		if got := question.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}
	}
}

// returned by 1.1.1.1 in response to the above query
// (though a different instance with different id)
var googleResponse = []byte{
	0x11, 0x31, // 0,  id
	0x81, 0x80, // 2,  flags
	0x00, 0x01, // 4,  num questions
	0x00, 0x01, // 6,  num answers
	0x00, 0x00, // 8,  num authority RRs
	0x00, 0x00, // 10, num additional RRs
	// question 1:
	0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // 12, "google"
	0x03, 0x63, 0x6f, 0x6d, // 19, "com"
	0x00,       // 23, end name
	0x00, 0x01, // 24, query type A
	0x00, 0x01, // 26, query class IN
	// answer 1:
	0xc0, 0x0c, // 28, pointer
	0x00, 0x01, // 30, query type A
	0x00, 0x01, // 32, query class IN
	0x00, 0x00, 0x00, 0x98, // 36, ttl
	0x00, 0x04, // 38, 4 bytes of data
	0xd8, 0x3a, 0xce, 0x4e, // 40, ip address
}

func TestParseResponse(t *testing.T) {
	q, err := dns.ParseDNSMessage(googleResponse)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}
	if got := q.ID; got != 0x1131 {
		t.Errorf("expected id 0x1131, got %x", q.ID)
	}

	flags := q.Flags
	if got := flags.Type(); got != dns.Response {
		t.Errorf("expected type Query, got %s", got)
	}
	if got := flags.OpCode(); got != dns.StandardQuery {
		t.Errorf("expected op code StandardQuery, got %s", got)
	}
	if got := flags.Authoritative(); got != false {
		t.Errorf("expected not authoritative, got %t", got)
	}
	if got := flags.Truncated(); got != false {
		t.Errorf("expected not truncated, got %t", got)
	}
	if got := flags.RecursionDesired(); got != true {
		t.Errorf("expected recursion desired, got %t", got)
	}
	if got := flags.RecursionAvailable(); got != true {
		t.Errorf("expected not recursion available, got %t", got)
	}
	if got := flags.ResponseCode(); got != dns.NoError {
		t.Errorf("expected no error, got %s", got)
	}

	questions := q.Questions
	if count := len(questions); count != 1 {
		t.Errorf("expected 1 question, got %d", count)
	} else {
		question := questions[0]
		if !slices.Equal(question.Names, []string{
			"google", "com",
		}) {
			t.Errorf("expected query for google.com, got %q",
				question.Names)
		}

		if got := question.Type; got != dns.A {
			t.Errorf("expected query type A, got %s", got)
		}

		if got := question.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}
	}

	answers := q.Answers
	if count := len(answers); count != 1 {
		t.Errorf("expected 1 answer, got %d", count)
	} else {
		answer := answers[0]

		if !slices.Equal(answer.Names, []string{
			"google", "com",
		}) {
			t.Errorf("expected query for google.com, got %q",
				answer.Names)
		}

		if got := answer.Type; got != dns.A {
			t.Errorf("expected query type A, got %s", got)
		}

		if got := answer.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}

		if answer.TTL != 0x98*time.Second {
			t.Errorf("expected ttl 98s but got %s", answer.TTL)
		}

		if ipv4, ok := answer.ResourceData.(net.IP); ok {
			if !ipv4.Equal(net.ParseIP("216.58.206.78")) {
				t.Errorf("expected addr 216.58.206.78 but got %s", ipv4)
			}
		} else {
			t.Errorf("expected ipv4 addr but got %T", answer.ResourceData)
		}
	}
}

var cnameWithMultipleAnswers = []byte{
	0xf2, 0xf2,
	0x81, 0x80,
	0x00, 0x01,
	0x00, 0x05,
	0x00, 0x00,
	0x00, 0x00,
	// question 1 - 12..
	0x03, 0x77, 0x77, 0x77,
	0x0c, 0x74, 0x68, 0x6f, 0x75, 0x67, 0x68, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x73,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
	0x00, 0x01,
	0x00, 0x01,
	// answer 1 - 38..
	0xc0, 0x0c,
	0x00, 0x05,
	0x00, 0x01,
	0x00, 0x00, 0x01, 0x2c,
	0x00, 0x1e,
	0x0d, 0x64, 0x73, 0x78, 0x73, 0x37, 0x6b, 0x35, 0x64, 0x71, 0x35, 0x71, 0x67, 0x6a,
	0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x72, 0x6f, 0x6e, 0x74,
	0x03, 0x6e, 0x65, 0x74,
	0x00,
	// answer 2
	0xc0, 0x32,
	0x00, 0x01,
	0x00, 0x01,
	0x00, 0x00, 0x00, 0x3c,
	0x00, 0x04,
	0x03, 0xa1, 0x52, 0x7a,
	// answer 3
	0xc0, 0x32,
	0x00, 0x01,
	0x00, 0x01,
	0x00, 0x00, 0x00, 0x3c,
	0x00, 0x04,
	0x03, 0xa1, 0x52, 0x70,
	// answer 4
	0xc0, 0x32,
	0x00, 0x01,
	0x00, 0x01,
	0x00, 0x00, 0x00, 0x3c,
	0x00, 0x04,
	0x03, 0xa1, 0x52, 0x36,
	// answer 5
	0xc0, 0x32,
	0x00, 0x01,
	0x00, 0x01,
	0x00, 0x00, 0x00, 0x3c,
	0x00, 0x04,
	0x03, 0xa1, 0x52, 0x7d,
}

func TestParseResponseWithCNAME(t *testing.T) {
	q, err := dns.ParseDNSMessage(cnameWithMultipleAnswers)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	if count := len(q.Answers); count != 5 {
		t.Fatalf("expected 5 answers, got %d", count)
	}

	for i, exp := range []dns.Answer{
		{
			Names: []string{
				"www",
				"thoughtworks",
				"com",
			},
			ResourceData: []string{
				"dsxs7k5dq5qgj",
				"cloudfront",
				"net",
			},
		},
		{
			Names: []string{
				"dsxs7k5dq5qgj",
				"cloudfront",
				"net",
			},
			ResourceData: net.ParseIP("3.161.82.122"),
		},
		{
			Names: []string{
				"dsxs7k5dq5qgj",
				"cloudfront",
				"net",
			},
			ResourceData: net.ParseIP("3.161.82.112"),
		},
		{
			Names: []string{
				"dsxs7k5dq5qgj",
				"cloudfront",
				"net",
			},
			ResourceData: net.ParseIP("3.161.82.54"),
		},
		{
			Names: []string{
				"dsxs7k5dq5qgj",
				"cloudfront",
				"net",
			},
			ResourceData: net.ParseIP("3.161.82.125"),
		},
	} {
		t.Run(fmt.Sprintf("answer %d", i), func(t *testing.T) {
			got := q.Answers[i]
			checkNameAndResourceData(t, exp, got)
		})
	}
}

func checkNameAndResourceData(
	t *testing.T,
	exp dns.Answer,
	got dns.Answer,
) {
	if !slices.Equal(got.Names, exp.Names) {
		t.Errorf("incorrect names\n  exp: %s,\n  got %s",
			exp.Names, got.Names)
	}

	expIP, expIsIP := exp.ResourceData.(net.IP)
	gotIP, gotIsIP := got.ResourceData.(net.IP)
	if expIsIP && gotIsIP {
		if !expIP.Equal(gotIP) {
			t.Errorf("incorrect resource data\n  exp %s\n  got %s",
				expIP, gotIP)
		}
	} else if !reflect.DeepEqual(exp.ResourceData, got.ResourceData) {
		t.Errorf("incorrect resource data\n  exp %#v\n  got %#v",
			exp.ResourceData, got.ResourceData)
	}
}

func TestRoundTripQuery(t *testing.T) {
	roundTripMessage(t, googleQuery)
}

func TestRoundTripResponse(t *testing.T) {
	roundTripMessage(t, googleResponse)
}

func roundTripMessage(t *testing.T, bytes []byte) {
	q, err := dns.ParseDNSMessage(bytes)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	var buf []byte
	buf, err = q.WriteTo(buf)
	if err != nil {
		t.Fatalf("unexpected error writing: %s", err)
	}

	q2, err := dns.ParseDNSMessage(buf)
	if err != nil {
		t.Fatalf("unexpected error re-parsing: %s", err)
	}

	if !reflect.DeepEqual(q, q2) {
		t.Errorf("re-parsed message is not same as original\n  exp %#v\n  got %#v",
			q, q2)
	}
}

func TestCompressionBasicQuery(t *testing.T) {
	reserialisingShouldntExpand(t, googleQuery)
}

func TestCompressionBasicResponse(t *testing.T) {
	reserialisingShouldntExpand(t, googleResponse)
}

func TestCompressionResponseWithCNAME(t *testing.T) {
	reserialisingShouldntExpand(t, cnameWithMultipleAnswers)
}

func reserialisingShouldntExpand(t *testing.T, original []byte) {
	q, err := dns.ParseDNSMessage(original)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	var reencoded []byte
	reencoded, err = q.WriteTo(reencoded)
	if err != nil {
		t.Fatalf("unexpected error writing: %s", err)
	}

	if len(reencoded) > len(original) {
		t.Errorf("reencoded message was larger than original (%d > %d)",
			len(reencoded), len(original))
	}
}

func TestMakeResponse(t *testing.T) {
	q, err := dns.ParseDNSMessage(googleQuery)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	rsp := dns.MakeResponse(q)
	if rsp.ID != q.ID {
		t.Errorf("same id in response but got %d", rsp.ID)
	}

	if rsp.Flags.Type() != dns.Response {
		t.Errorf("expected Response type but got %s", rsp.Flags.Type())
	}

	if rsp.Flags.OpCode() != dns.StandardQuery {
		t.Errorf("expected standard query opcode but got %s",
			rsp.Flags.OpCode())
	}

	// other fields should be same but possibly set later by app

	if rsp.Flags.ResponseCode() != dns.NoError {
		t.Errorf("expected No Error but got %s", rsp.Flags.ResponseCode())
	}

	if !reflect.DeepEqual(q.Questions, rsp.Questions) {
		t.Errorf("expected same questions in rsp\n  exp %#v\n  got %#v",
			q.Questions, rsp.Questions)
	}
}
