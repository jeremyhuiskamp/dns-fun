package dns_test

import (
	"dns"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"
)

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
	q, err := dns.ParseMessage(googleQuery)
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
		if !slices.Equal(question.Name, name("google", "com")) {
			t.Errorf("expected query for google.com, got %q",
				question.Name)
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
	rsp, err := dns.ParseMessage(googleResponse)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}
	if got := rsp.ID; got != 0x1131 {
		t.Errorf("expected id 0x1131, got %x", rsp.ID)
	}

	flags := rsp.Flags
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

	questions := rsp.Questions
	if count := len(questions); count != 1 {
		t.Errorf("expected 1 question, got %d", count)
	} else {
		question := questions[0]
		if !slices.Equal(question.Name, name("google", "com")) {
			t.Errorf("expected query for google.com, got %q",
				question.Name)
		}

		if got := question.Type; got != dns.A {
			t.Errorf("expected query type A, got %s", got)
		}

		if got := question.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}
	}

	answers := rsp.Answers
	if count := len(answers); count != 1 {
		t.Errorf("expected 1 answer, got %d", count)
	} else {
		answer := answers[0]

		if !slices.Equal(answer.Name, dns.Name([]dns.Label{
			"google", "com",
		})) {
			t.Errorf("expected query for google.com, got %q",
				answer.Name)
		}

		if got := answer.Type; got != dns.A {
			t.Errorf("expected query type A, got %s", got)
		}

		if got := answer.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}

		if answer.TTL != 0x98*time.Second {
			t.Errorf("expected ttl 0x98s but got %s", answer.TTL)
		}

		if ipv4, ok := answer.Data.(net.IP); ok {
			if !ipv4.Equal(net.ParseIP("216.58.206.78")) {
				t.Errorf("expected addr 216.58.206.78 but got %s", ipv4)
			}
		} else {
			t.Errorf("expected ipv4 addr but got %T", answer.Data)
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
	rsp, err := dns.ParseMessage(cnameWithMultipleAnswers)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	if count := len(rsp.Answers); count != 5 {
		t.Fatalf("expected 5 answers, got %d", count)
	}

	for i, exp := range []dns.Resource{
		{
			Name: name("www", "thoughtworks", "com"),
			Data: name("dsxs7k5dq5qgj", "cloudfront", "net"),
		},
		{
			Name: name("dsxs7k5dq5qgj", "cloudfront", "net"),
			Data: net.ParseIP("3.161.82.122"),
		},
		{
			Name: name("dsxs7k5dq5qgj", "cloudfront", "net"),
			Data: net.ParseIP("3.161.82.112"),
		},
		{
			Name: name("dsxs7k5dq5qgj", "cloudfront", "net"),
			Data: net.ParseIP("3.161.82.54"),
		},
		{
			Name: name("dsxs7k5dq5qgj", "cloudfront", "net"),
			Data: net.ParseIP("3.161.82.125"),
		},
	} {
		t.Run(fmt.Sprintf("answer %d", i), func(t *testing.T) {
			got := rsp.Answers[i]
			checkNameAndData(t, exp, got)
		})
	}
}

func checkNameAndData(
	t *testing.T,
	exp dns.Resource,
	got dns.Resource,
) {
	if !slices.Equal(got.Name, exp.Name) {
		t.Errorf("incorrect name\n  exp: %s,\n  got %s",
			exp.Name, got.Name)
	}

	expIP, expIsIP := exp.Data.(net.IP)
	gotIP, gotIsIP := got.Data.(net.IP)
	if expIsIP && gotIsIP {
		if !expIP.Equal(gotIP) {
			t.Errorf("incorrect resource data\n  exp %s\n  got %s",
				expIP, gotIP)
		}
	} else if !reflect.DeepEqual(exp.Data, got.Data) {
		t.Errorf("incorrect resource data\n  exp %#v\n  got %#v",
			exp.Data, got.Data)
	}
}

func TestRoundTripQuery(t *testing.T) {
	roundTripMessage(t, googleQuery)
}

func TestRoundTripResponse(t *testing.T) {
	roundTripMessage(t, googleResponse)
}

func roundTripMessage(t *testing.T, bytes []byte) {
	msg, err := dns.ParseMessage(bytes)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	var buf []byte
	buf, err = msg.WriteTo(buf)
	if err != nil {
		t.Fatalf("unexpected error writing: %s", err)
	}

	q2, err := dns.ParseMessage(buf)
	if err != nil {
		t.Fatalf("unexpected error re-parsing: %s", err)
	}

	// repurpose the buffer to make sure the message is not keeping any
	// references to it:
	clear(buf)

	if !reflect.DeepEqual(msg, q2) {
		t.Errorf("re-parsed message is not same as original\n  exp %#v\n  got %#v",
			msg, q2)
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
	msg, err := dns.ParseMessage(original)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	var reencoded []byte
	reencoded, err = msg.WriteTo(reencoded)
	if err != nil {
		t.Fatalf("unexpected error writing: %s", err)
	}

	if len(reencoded) > len(original) {
		t.Errorf("reencoded message was larger than original (%d > %d)",
			len(reencoded), len(original))
	}
}

func TestMakeResponse(t *testing.T) {
	q, err := dns.ParseMessage(googleQuery)
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

var googleAAAAResponse = []byte{
	0x65, 0xe5,
	0x81, 0x80,
	0x00, 0x01,
	0x00, 0x01,
	0x00, 0x00,
	0x00, 0x00,
	// question 1
	0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
	0x00, 0x1c, // AAAA
	0x00, 0x01,
	// answer 1
	0xc0, 0x0c,
	0x00, 0x1c, // AAAA
	0x00, 0x01,
	0x00, 0x00, 0x00, 0x62,
	0x00, 0x10, // length 16
	0x2a, 0x00, 0x14, 0x50, // ipv6 addr
	0x40, 0x01, 0x08, 0x13, // ...
	0x00, 0x00, 0x00, 0x00, // ...
	0x00, 0x00, 0x20, 0x0e, // ...
}

func TestParseAAAAResponse(t *testing.T) {
	rsp, err := dns.ParseMessage(googleAAAAResponse)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	questions := rsp.Questions
	if count := len(questions); count != 1 {
		t.Errorf("expected 1 question, got %d", count)
	} else {
		question := questions[0]
		if !slices.Equal(question.Name, name("google", "com")) {
			t.Errorf("expected query for google.com, got %q",
				question.Name)
		}

		if got := question.Type; got != dns.AAAA {
			t.Errorf("expected query type AAAA, got %s", got)
		}

		if got := question.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}
	}

	answers := rsp.Answers
	if count := len(answers); count != 1 {
		t.Errorf("expected 1 answer, got %d", count)
	} else {
		answer := answers[0]

		if !slices.Equal(answer.Name, name("google", "com")) {
			t.Errorf("expected query for google.com, got %q",
				answer.Name)
		}

		if got := answer.Type; got != dns.AAAA {
			t.Errorf("expected query type AAAA, got %s", got)
		}

		if got := answer.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}

		if answer.TTL != 98*time.Second {
			t.Errorf("expected ttl 98s but got %s", answer.TTL)
		}

		if ip, ok := answer.Data.(net.IP); ok {
			exp := "2a00:1450:4001:813::200e"
			if !ip.Equal(net.ParseIP(exp)) {
				t.Errorf("expected addr %s but got %s", exp, ip)
			}
		} else {
			t.Errorf("expected ip addr but got %T", answer.Data)
		}
	}
}

func TestRoundTripAAAAResponse(t *testing.T) {
	roundTripMessage(t, googleAAAAResponse)
}

func TestCompressionAAAAResponse(t *testing.T) {
	reserialisingShouldntExpand(t, googleAAAAResponse)
}

var googleMXResponse = []byte{
	0x8a, 0xb1,
	0x81, 0x80,
	0x00, 0x01,
	0x00, 0x01,
	0x00, 0x00,
	0x00, 0x00,
	// question
	0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
	0x00, 0x0f, // MX
	0x00, 0x01,
	// answer
	0xc0, 0x0c,
	0x00, 0x0f,
	0x00, 0x01,
	0x00, 0x00, 0x01, 0x2c,
	0x00, 0x09,
	0x00, 0x0a, // preference
	0x04, 0x73, 0x6d, 0x74, 0x70, 0xc0, 0x0c, // host
}

func TestParseMXResponse(t *testing.T) {
	rsp, err := dns.ParseMessage(googleMXResponse)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	questions := rsp.Questions
	if count := len(questions); count != 1 {
		t.Errorf("expected 1 question, got %d", count)
	} else {
		question := questions[0]
		if !slices.Equal(question.Name, name("google", "com")) {
			t.Errorf("expected query for google.com, got %q",
				question.Name)
		}

		if got := question.Type; got != dns.MX {
			t.Errorf("expected query type MX, got %s", got)
		}

		if got := question.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}
	}

	answers := rsp.Answers
	if count := len(answers); count != 1 {
		t.Errorf("expected 1 answer, got %d", count)
	} else {
		answer := answers[0]

		if !slices.Equal(answer.Name, name("google", "com")) {
			t.Errorf("expected query for google.com, got %q",
				answer.Name)
		}

		if got := answer.Type; got != dns.MX {
			t.Errorf("expected query type MX, got %s", got)
		}

		if got := answer.Class; got != dns.IN {
			t.Errorf("expected query class IN, got %s", got)
		}

		if answer.TTL != 5*time.Minute {
			t.Errorf("expected ttl 5m but got %s", answer.TTL)
		}

		if mx, ok := answer.Data.(dns.MXRecord); !ok {
			t.Errorf("expected MX record but got %T", answer.Data)
		} else {
			if mx.Preference != 10 {
				t.Errorf("expected preference 10, but got %d",
					mx.Preference)
			}
			if !slices.Equal(mx.MailExchange, name("smtp", "google", "com")) {
				t.Errorf("expected mail exchange smtp.google.com, got %s",
					mx.MailExchange)
			}
		}
	}
}

func TestRoundTripMXResponse(t *testing.T) {
	roundTripMessage(t, googleMXResponse)
}

func TestCompressionMXResponse(t *testing.T) {
	reserialisingShouldntExpand(t, googleMXResponse)
}

// Obtained by querying a root server for google.com, A records.
// Due to the size, this happened over tcp.  The 16-byte length
// prefix has been removed.
var googleRootAResponse = []byte{
	0x29, 0xc0, // ID
	0x81, 0x00, // flags
	0x00, 0x01, // # questions
	0x00, 0x00, // # answers
	0x00, 0x0d, // # authorties
	0x00, 0x1a, // # additional RRs
	// question
	0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
	0x03, 0x63, 0x6f, 0x6d, // com
	0x00,
	0x00, 0x01, 0x00, 0x01,
	// authority 1
	0xc0, 0x13, // com
	0x00, 0x02, // NS
	0x00, 0x01, // IN
	0x00, 0x02, 0xa3, 0x00, // TTL 2 days
	0x00, 0x14, // data length 20
	0x01, 0x6c, // l
	0x0c, 0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, // gtld-servers
	0x03, 0x6e, 0x65, 0x74, // net
	0x00, // .
	// authority 2
	0xc0, 0x13, // com
	0x00, 0x02, // NS
	0x00, 0x01, // IN
	0x00, 0x02, 0xa3, 0x00, // TTL
	0x00, 0x04, // data length 4
	0x01, 0x6a, // j
	0xc0, 0x2a, // gtld-servers.net
	// authority 3
	0xc0, 0x13, // com
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x68, // h
	0xc0, 0x2a,
	// authority 4
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x64, // d
	0xc0, 0x2a,
	// authority 5
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x62, // b
	0xc0, 0x2a,
	// authority 6
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x66, // f
	0xc0, 0x2a,
	// authority 7
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x6b, // k
	0xc0, 0x2a,
	// authority 8
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x6d, // m
	0xc0, 0x2a,
	// authority 9
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x69, // i
	0xc0, 0x2a,
	// authority 10
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x67, // g
	0xc0, 0x2a,
	// authority 11
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x61, // a
	0xc0, 0x2a,
	// authority 12
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x63, // c
	0xc0, 0x2a,
	// authority 13
	0xc0, 0x13,
	0x00, 0x02,
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0x01, 0x65, // e
	0xc0, 0x2a,
	// additional record 1
	0xc0, 0x28, // l.gtld-servers.net
	0x00, 0x01, // A
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0xc0, 0x29, 0xa2, 0x1e,
	// aditional record 2
	0xc0, 0x28, // l.gtld...
	0x00, 0x1c, // AAAA
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x10,
	0x20, 0x01, 0x05, 0x00, 0xd9, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 3
	0xc0, 0x48, // j.gtld...
	0x00, 0x01, // A
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0xc0, 0x30, 0x4f, 0x1e,
	// additional record 4
	0xc0, 0x48, // j.gtld...
	0x00, 0x1c, // AAAA
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x10,
	0x20, 0x01, 0x05, 0x02, 0x70, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 5
	0xc0, 0x58, // h.gtld...
	0x00, 0x01, // A
	0x00, 0x01,
	0x00, 0x02, 0xa3, 0x00,
	0x00, 0x04,
	0xc0, 0x36, 0x70, 0x1e,
	// additional record 6
	0xc0, 0x58, // h.gtld...
	0x00, 0x1c, // AAAA
	0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x02, 0x08, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 7
	0xc0, 0x68, // d.gtld...
	0x00, 0x01,
	0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x1f, 0x50, 0x1e,
	// additional record 8
	0xc0, 0x68, // d.gtld...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x85, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 9
	0xc0, 0x78, // b.gtld...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x21, 0x0e, 0x1e,
	// additional record 10
	0xc0, 0x78, // b.gtld...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x23, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x30,
	// additional record 11
	0xc0, 0x88, // f...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x23, 0x33, 0x1e,
	// additional record 12
	0xc0, 0x88, // f...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xd4, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 13
	0xc0, 0x98, // k...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x34, 0xb2, 0x1e,
	// additional record 14
	0xc0, 0x98, // k...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x0d, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 15
	0xc0, 0xa8, // m...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x37, 0x53, 0x1e,
	// additional record 16
	0xc0, 0xa8, // m...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x01, 0xb1, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 17
	0xc0, 0xb8, // i...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x2b, 0xac, 0x1e,
	// additional record 18
	0xc0, 0xb8, // i...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x39, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 19
	0xc0, 0xc8, // g...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x2a, 0x5d, 0x1e,
	// additional record 20
	0xc0, 0xc8, // g...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xee, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 21
	0xc0, 0xd8, // a...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x05, 0x06, 0x1e,
	// additional record 22
	0xc0, 0xd8, // a...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xa8, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x30,
	// additional record 23
	0xc0, 0xe8, // c...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x1a, 0x5c, 0x1e,
	// additional record 24
	0xc0, 0xe8, // c...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x83, 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
	// additional record 25
	0xc0, 0xf8, // e...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x0c, 0x5e, 0x1e,
	// additional record 26
	0xc0, 0xf8, // e...
	0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x02, 0x1c, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
}

func TestParseGoogleRootAResponses(t *testing.T) {
	rsp, err := dns.ParseMessage(googleRootAResponse)
	if err != nil {
		t.Fatalf("unexpected error parsing: %s", err)
	}

	if len(rsp.Answers) != 0 {
		t.Errorf("expected 0 answers, got %d", len(rsp.Answers))
	}

	if len(rsp.Authorities) != 13 {
		t.Errorf("expected 13 authorities, got %d", len(rsp.Authorities))
	}
	checkNS(t, rsp.Authorities, 0, "l", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 1, "j", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 2, "h", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 3, "d", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 4, "b", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 5, "f", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 6, "k", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 7, "m", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 8, "i", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 9, "g", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 10, "a", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 11, "c", "gtld-servers", "net")
	checkNS(t, rsp.Authorities, 12, "e", "gtld-servers", "net")

	if len(rsp.Additional) != 26 {
		t.Errorf("expected 26 additional records, got %d", len(rsp.Additional))
	}
	checkIP(t, rsp.Additional, 0, dns.A, "192.41.162.30", "l", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 1, dns.AAAA, "2001:500:d937::30", "l", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 2, dns.A, "192.48.79.30", "j", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 3, dns.AAAA, "2001:502:7094::30", "j", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 4, dns.A, "192.54.112.30", "h", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 5, dns.AAAA, "2001:502:8cc::30", "h", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 6, dns.A, "192.31.80.30", "d", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 7, dns.AAAA, "2001:500:856e::30", "d", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 8, dns.A, "192.33.14.30", "b", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 9, dns.AAAA, "2001:503:231d::2:30", "b", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 10, dns.A, "192.35.51.30", "f", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 11, dns.AAAA, "2001:503:d414::30", "f", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 12, dns.A, "192.52.178.30", "k", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 13, dns.AAAA, "2001:503:d2d::30", "k", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 14, dns.A, "192.55.83.30", "m", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 15, dns.AAAA, "2001:501:b1f9::30", "m", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 16, dns.A, "192.43.172.30", "i", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 17, dns.AAAA, "2001:503:39c1::30", "i", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 18, dns.A, "192.42.93.30", "g", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 19, dns.AAAA, "2001:503:eea3::30", "g", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 20, dns.A, "192.5.6.30", "a", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 21, dns.AAAA, "2001:503:a83e::2:30", "a", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 22, dns.A, "192.26.92.30", "c", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 23, dns.AAAA, "2001:503:83eb::30", "c", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 24, dns.A, "192.12.94.30", "e", "gtld-servers", "net")
	checkIP(t, rsp.Additional, 25, dns.AAAA, "2001:502:1ca1::30", "e", "gtld-servers", "net")
}

func checkNS(t *testing.T, authorities []dns.Resource, i int, expName ...dns.Label) {
	t.Helper()
	authority := authorities[i]
	if authority.Type != dns.NS {
		t.Errorf("authority %d expected to be NS, got %s",
			i, authority.Type)
	}

	gotName, _ := authority.Data.(dns.Name)
	if !slices.Equal(gotName, expName) {
		t.Errorf("authority %d has unexpected name\n  exp %q\n  got %q",
			i, expName, gotName)
	}
}

func checkIP(
	t *testing.T,
	additionals []dns.Resource,
	i int,
	expType dns.QueryType,
	expIP string,
	expName ...dns.Label,
) {
	additional := additionals[i]
	if additional.Type != expType {
		t.Errorf("additional %d expected type %s got %s",
			i, expType, additional.Type)
	}

	if gotIP, ok := additional.Data.(net.IP); !ok {
		t.Errorf("additional %d expected net.IP data, got %T",
			i, additional.Data)
	} else if !net.ParseIP(expIP).Equal(gotIP) {
		t.Errorf("additional %d unexpected ip address\n  exp %s\n  got %s",
			i, expIP, gotIP)
	}

	if !slices.Equal(additional.Name, expName) {
		t.Errorf("additional %d has unexpected name\n  exp %q\n  got %q",
			i, expName, additional.Name)
	}
}

func TestRoundTripRootAResponse(t *testing.T) {
	roundTripMessage(t, googleRootAResponse)
}

func TestCompressionRootAResponse(t *testing.T) {
	reserialisingShouldntExpand(t, googleRootAResponse)
}

var compressionWithLoop = []byte{
	0x67, 0x6c, // ID
	0x01, 0x00, // flags
	0x00, 0x01, // # questions
	0x00, 0x00, // # answers
	0x00, 0x00, // # authority RRs
	0x00, 0x00, // # additional RRs
	// question 1
	0xc0, 0x0c, // point to location 12, this very location!
}

func TestCompressionWithLoop(t *testing.T) {
	_, err := dns.ParseMessage(compressionWithLoop)
	if err != dns.ErrInvalidCompression {
		t.Errorf("expected error for invalid compression, but got %s", err)
	}
}

func TestShortBufGoogleRootAResponse(t *testing.T) {
	checkShortBufProducesProperError(t, googleRootAResponse)
}

// checkShortBufProducesProperError parses every possible truncation of the msg
// and expects them all to return ErrShortBuf
func checkShortBufProducesProperError(t *testing.T, msg []byte) {
	_, err := dns.ParseMessage(msg)
	if err != nil {
		t.Errorf(
			"expected no error when parsing entire message, but got %s",
			err,
		)
	}

	for trim := 1; trim <= len(msg); trim++ {
		shortMsg := msg[:len(msg)-trim]
		_, err := dns.ParseMessage(shortMsg)
		if err != io.ErrShortBuffer {
			t.Errorf(
				"expected short buffer error after trimming %d bytes from message, but got %s",
				trim, err,
			)
		}
	}
}

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

func name(labels ...dns.Label) dns.Name {
	return dns.Name(labels)
}
