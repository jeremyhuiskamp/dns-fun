package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func ParseDNSMessage(buf []byte) (DNSMessage, error) {
	if len(buf) < 12 {
		return DNSMessage{}, io.ErrShortBuffer
	}

	questions, offset, err := parseQuestions(buf)
	if err != nil {
		return DNSMessage{}, err
	}

	answers, _, err := parseAnswers(buf, offset)
	if err != nil {
		return DNSMessage{}, err
	}

	return DNSMessage{
		ID:        be.Uint16(buf),
		Flags:     Flags(be.Uint16(buf[2:])),
		Questions: questions,
		Answers:   answers,
	}, nil
}

func MakeResponse(qry DNSMessage) DNSMessage {
	// TODO: we should probably set a few more flags explicitly
	// eg, ResponseCode, etc
	return DNSMessage{
		ID:        qry.ID,
		Flags:     qry.Flags.WithType(Response),
		Questions: qry.Questions,
	}
}

type DNSMessage struct {
	ID        uint16
	Flags     Flags
	Questions []Question
	Answers   []Answer
}

func (m DNSMessage) WriteTo(buf []byte) ([]byte, error) {
	buf = be.AppendUint16(buf, m.ID)
	buf = be.AppendUint16(buf, uint16(m.Flags))
	buf = be.AppendUint16(buf, uint16(len(m.Questions)))
	buf = be.AppendUint16(buf, uint16(len(m.Answers)))
	buf = be.AppendUint16(buf, 0)
	buf = be.AppendUint16(buf, 0)

	nc := NewNameCompressor()

	for _, question := range m.Questions {
		buf = appendNames(buf, nc, question.Names)

		buf = be.AppendUint16(buf, uint16(question.Type))
		buf = be.AppendUint16(buf, uint16(question.Class))
	}

	for _, answer := range m.Answers {
		buf = appendNames(buf, nc, answer.Names)

		buf = be.AppendUint16(buf, uint16(answer.Type))
		buf = be.AppendUint16(buf, uint16(answer.Class))

		buf = be.AppendUint32(buf, uint32(answer.TTL.Seconds()))

		switch answer.Type {
		case A:
			buf = be.AppendUint16(buf, 4)
			ip, ok := answer.ResourceData.(net.IP)
			if !ok || ip.To4() == nil {
				return nil, errors.New("mismatched resource type")
			}
			buf = append(buf, ip.To4()...)
		case AAAA:
			buf = be.AppendUint16(buf, 16)
			ip, ok := answer.ResourceData.(net.IP)
			if !ok || ip.To16() == nil {
				return nil, errors.New("mismatched resource type")
			}
			buf = append(buf, ip.To16()...)
		case CNAME:
			names, ok := answer.ResourceData.([]string)
			if !ok {
				return nil, fmt.Errorf("mismatched resource type %s / %T",
					answer.Type, answer.ResourceData)
			}
			lenOffset := len(buf)
			buf = be.AppendUint16(buf, 0) // placeholder
			lenBeforeNames := len(buf)
			buf = appendNames(buf, nc, names)
			lenAfterNames := len(buf)
			be.PutUint16(buf[lenOffset:], uint16(lenAfterNames-lenBeforeNames))
		default:
			bytes, ok := answer.ResourceData.([]byte)
			if !ok {
				return nil, fmt.Errorf("mismatched resource type %s / %T",
					answer.Type, answer.ResourceData)
			}
			buf = be.AppendUint16(buf, uint16(len(bytes)))
			buf = append(buf, bytes...)
		}
	}

	return buf, nil
}

func appendNames(buf []byte, nc NameCompressor, names []string) []byte {
	skip, offset := nc.Lookup(names)
	nc.Record(uint16(len(buf)), names)

	for _, name := range names[:skip] {
		buf = append(buf, byte(len(name)))
		buf = append(buf, []byte(name)...)
	}

	if offset > 0 {
		buf = be.AppendUint16(buf, 0b1100_0000_0000_0000|offset)
	} else {
		buf = append(buf, 0)
	}

	return buf
}

func parseQuestions(buf []byte) ([]Question, int, error) {
	numQuestions := be.Uint16(buf[4:])
	if numQuestions == 0 {
		return nil, 0, nil
	}

	offset := 12
	questions := make([]Question, numQuestions)
	for i := range numQuestions {
		var question Question
		var err error
		question, offset, err = parseQuestion(buf, offset)
		if err != nil {
			return nil, 0, err
		}
		questions[i] = question
	}

	return questions, offset, nil
}

func parseAnswers(buf []byte, offset int) ([]Answer, int, error) {
	numAnswers := be.Uint16(buf[6:])
	if numAnswers == 0 {
		return nil, offset, nil
	}
	answers := make([]Answer, numAnswers)
	for i := range numAnswers {
		var answer Answer
		var err error
		answer, offset, err = parseAnswer(buf, offset)
		if err != nil {
			return nil, 0, err
		}
		answers[i] = answer
	}
	return answers, offset, nil
}

func (m DNSMessage) String() string {
	return fmt.Sprintf("DNS Message: %d, %s, %s, %t",
		m.ID,
		m.Flags.Type(),
		m.Flags.OpCode(),
		m.Flags.Authoritative(),
	)
}

//go:generate stringer -type=DNSType
type DNSType byte

const (
	Query    DNSType = 0
	Response DNSType = 1
)

//go:generate stringer -type=OpCode
type OpCode byte

const (
	StandardQuery       OpCode = 0
	InverseQuery        OpCode = 1
	ServerStatusRequest OpCode = 2
	OpCodeMask          byte   = 0b0111_1000
)

//go:generate stringer -type=ResponseCode
type ResponseCode byte

const (
	NoError        ResponseCode = 0
	FormatError    ResponseCode = 1
	ServerFailure  ResponseCode = 2
	NameError      ResponseCode = 3
	NotImplemented ResponseCode = 4
	Refused        ResponseCode = 5
)

type Flags uint16

func (f Flags) boolInBit(bit uint8) bool {
	var mask uint16 = 1 << bit
	return uint16(f)&mask == mask
}

func (f Flags) withBoolInBit(bit uint8, val bool) Flags {
	var mask uint16 = 1 << bit
	if val {
		return Flags(uint16(f) | mask)
	} else {
		return Flags(uint16(f) &^ mask)
	}
}

func (f Flags) Type() DNSType {
	return DNSType(uint16(f) >> 15)
}

func (f Flags) WithType(t DNSType) Flags {
	var mask uint16 = 1 << 15
	var val = uint16(t) << 15
	return Flags(uint16(f)&^mask | val)
}

func (f Flags) OpCode() OpCode {
	return OpCode(uint16(f)>>11) & 0xf
}

func (f Flags) Authoritative() bool {
	return f.boolInBit(10)
}

func (f Flags) WithAuthoritiative(val bool) Flags {
	return f.withBoolInBit(10, val)
}

func (f Flags) Truncated() bool {
	return f.boolInBit(9)
}

func (f Flags) RecursionDesired() bool {
	return f.boolInBit(8)
}

func (f Flags) RecursionAvailable() bool {
	return f.boolInBit(7)
}

// TODO: there are more flags in here
// TCP/IP Illustrated says there are 3 reserved bits here
// but wireshark shows some info about authentication in
// 2 of them...

func (f Flags) ResponseCode() ResponseCode {
	return ResponseCode(uint16(f) & 0b1111)
}

type Question struct {
	Names []string
	Type  QueryType
	Class QueryClass
}

func parseQuestion(buf []byte, offset int) (Question, int, error) {
	if len(buf) < 1 {
		return Question{}, 0, io.ErrShortBuffer
	}

	names, offset, err := parseNames(buf, offset)
	if err != nil {
		return Question{}, 0, err
	}

	if len(buf[offset:]) < 4 {
		return Question{}, 0, io.ErrShortBuffer
	}

	qType := QueryType(be.Uint16(buf[offset:]))
	offset += 2
	qClass := QueryClass(be.Uint16(buf[offset:]))
	offset += 2

	return Question{
		Names: names,
		Type:  qType,
		Class: qClass,
	}, offset, nil
}

//go:generate stringer -type=QueryType
type QueryType uint16

// TODO: more from https://en.wikipedia.org/wiki/List_of_DNS_record_types
const (
	A     QueryType = 1
	NS    QueryType = 2
	MD    QueryType = 3
	MF    QueryType = 4
	CNAME QueryType = 5
	SOA   QueryType = 6
	MB    QueryType = 7
	MG    QueryType = 8
	MR    QueryType = 9
	NULL  QueryType = 10
	WKS   QueryType = 11
	PTR   QueryType = 12
	HINFO QueryType = 13
	MINFO QueryType = 14
	MX    QueryType = 15
	TXT   QueryType = 16

	AAAA QueryType = 28

	AXFR      QueryType = 252
	MAILB     QueryType = 253
	MAILA     QueryType = 254
	ANY_QUERY QueryType = 255
)

//go:generate stringer -type=QueryClass
type QueryClass uint16

const (
	IN QueryClass = 1
	CS QueryClass = 2
	CH QueryClass = 3
	HS QueryClass = 4

	ANY_CLASS QueryClass = 255
)

type Answer struct {
	Names        []string
	Type         QueryType
	Class        QueryClass
	TTL          time.Duration
	ResourceData any
}

func parseAnswer(buf []byte, offset int) (Answer, int, error) {
	if len(buf) < 2 {
		return Answer{}, 0, io.ErrShortBuffer
	}

	names, offset, err := parseNames(buf, offset)
	if err != nil {
		return Answer{}, 0, err
	}

	if len(buf[offset:]) < 10 {
		return Answer{}, 0, io.ErrShortBuffer
	}

	qType := QueryType(be.Uint16(buf[offset:]))
	offset += 2
	qClass := QueryClass(be.Uint16(buf[offset:]))
	offset += 2

	ttl := time.Second * time.Duration(be.Uint32(buf[offset:]))
	offset += 4

	resourceDataLen := be.Uint16(buf[offset:])
	offset += 2

	if len(buf[offset:]) < int(resourceDataLen) {
		return Answer{}, 0, io.ErrShortBuffer
	}

	resourceDataBytes := buf[offset:][:resourceDataLen]
	var resourceData any
	if qType == A && resourceDataLen == 4 {
		resourceData = net.IP(resourceDataBytes)
	} else if qType == AAAA && resourceDataLen == 16 {
		resourceData = net.IP(resourceDataBytes)
	} else if qType == CNAME {
		resourceData, _, err = parseNames(buf, offset)
		if err != nil {
			return Answer{}, 0, err
		}
	} else {
		// fallback on raw bytes
		// TODO: other types...
		resourceData = resourceDataBytes
	}
	offset += int(resourceDataLen)

	return Answer{
		Names:        names,
		Type:         qType,
		Class:        qClass,
		TTL:          ttl,
		ResourceData: resourceData,
	}, offset, nil
}

func parseNames(buf []byte, offset int) ([]string, int, error) {
	if len(buf[offset:]) < 1 {
		return nil, 0, io.ErrShortBuffer
	}

	var names []string
	nameLen := uint(buf[offset])
	for nameLen > 0 {
		if nameLen&0b1100_0000 == 0b1100_0000 {
			if len(buf[offset:]) < 2 {
				return nil, 0, io.ErrShortBuffer
			}
			newOffset := be.Uint16(buf[offset:])
			offset += 2
			newOffset &= 0b0011_1111_1111_1111
			pointerNames, _, err := parseNames(buf, int(newOffset))
			return append(names, pointerNames...), offset, err
		}

		offset++
		if len(buf[offset:]) < int(nameLen)+1 {
			return nil, 0, io.ErrShortBuffer
		}

		// TODO: punycode parsing?
		name := string(buf[offset:][:nameLen])
		names = append(names, name)
		offset += int(nameLen)
		nameLen = uint(buf[offset])
	}

	// skip over 0
	// Don't do this directly after reading nameLen because
	// we might need to re-read it as part of a pointer.
	offset++

	return names, offset, nil
}

var be = binary.BigEndian
