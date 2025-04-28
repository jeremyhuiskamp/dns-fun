package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func ParseDNSMessage(b []byte) (DNSMessage, error) {
	buf := readBuf{b, 0}

	id, _ := buf.Uint16()
	flags, _ := as[Flags](buf.Uint16())
	numQuestions, _ := buf.Uint16()
	numAnswers, _ := buf.Uint16()
	numAuthorities, _ := buf.Uint16()
	numAdditional, err := buf.Uint16()

	if err != nil {
		return DNSMessage{}, io.ErrShortBuffer
	}

	questions, buf, err := parseQuestions(buf, numQuestions)
	if err != nil {
		return DNSMessage{}, err
	}

	answers, buf, err := parseResources(buf, numAnswers)
	if err != nil {
		return DNSMessage{}, err
	}

	authorities, buf, err := parseResources(buf, numAuthorities)
	if err != nil {
		return DNSMessage{}, err
	}

	additional, buf, err := parseResources(buf, numAdditional)
	if err != nil {
		return DNSMessage{}, err
	}

	return DNSMessage{
		ID:          id,
		Flags:       flags,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additional:  additional,
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
	ID          uint16
	Flags       Flags
	Questions   []Question
	Answers     []Resource
	Authorities []Resource
	Additional  []Resource
}

func (m DNSMessage) WriteTo(buf []byte) ([]byte, error) {
	buf = be.AppendUint16(buf, m.ID)
	buf = be.AppendUint16(buf, uint16(m.Flags))
	buf = be.AppendUint16(buf, uint16(len(m.Questions)))
	buf = be.AppendUint16(buf, uint16(len(m.Answers)))
	buf = be.AppendUint16(buf, uint16(len(m.Authorities)))
	buf = be.AppendUint16(buf, uint16(len(m.Additional)))

	nc := NewNameCompressor()

	for _, question := range m.Questions {
		buf = appendNames(buf, nc, question.Names)

		buf = be.AppendUint16(buf, uint16(question.Type))
		buf = be.AppendUint16(buf, uint16(question.Class))
	}

	for _, res := range m.Answers {
		var err error
		buf, err = writeResource(buf, nc, res)
		if err != nil {
			return nil, err
		}
	}

	for _, res := range m.Authorities {
		var err error
		buf, err = writeResource(buf, nc, res)
		if err != nil {
			return nil, err
		}
	}

	for _, res := range m.Additional {
		var err error
		buf, err = writeResource(buf, nc, res)
		if err != nil {
			return nil, err
		}
	}

	return buf, nil
}

func writeResource(buf []byte, nc NameCompressor, res Resource) ([]byte, error) {
	buf = appendNames(buf, nc, res.Names)

	buf = be.AppendUint16(buf, uint16(res.Type))
	buf = be.AppendUint16(buf, uint16(res.Class))

	buf = be.AppendUint32(buf, uint32(res.TTL.Seconds()))

	switch res.Type {
	case A:
		buf = be.AppendUint16(buf, 4)
		ip, ok := res.Data.(net.IP)
		if !ok || ip.To4() == nil {
			return nil, errors.New("mismatched resource type")
		}
		buf = append(buf, ip.To4()...)
	case NS:
		names, ok := res.Data.([]string)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = writeVariableLengthDataToBuf(buf, func(buf []byte) []byte {
			return appendNames(buf, nc, names)
		})
	case AAAA:
		buf = be.AppendUint16(buf, 16)
		ip, ok := res.Data.(net.IP)
		if !ok || ip.To16() == nil {
			return nil, errors.New("mismatched resource type")
		}
		buf = append(buf, ip.To16()...)
	case CNAME:
		names, ok := res.Data.([]string)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = writeVariableLengthDataToBuf(buf, func(buf []byte) []byte {
			return appendNames(buf, nc, names)
		})
	case MX:
		mx, ok := res.Data.(MXRecord)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = writeVariableLengthDataToBuf(buf, func(buf []byte) []byte {
			buf = be.AppendUint16(buf, mx.Preference)
			return appendNames(buf, nc, mx.MailExchange)
		})
	default:
		bytes, ok := res.Data.([]byte)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = be.AppendUint16(buf, uint16(len(bytes)))
		buf = append(buf, bytes...)
	}

	return buf, nil
}

// writeVariableLengthDataToBuf wraps another function to
// prefix the data written with its length.
func writeVariableLengthDataToBuf(buf []byte, doWrite func(buf []byte) []byte) []byte {
	lenOffset := len(buf)
	buf = be.AppendUint16(buf, 0) // placeholder
	lenBeforeData := len(buf)
	buf = doWrite(buf)
	dataLen := len(buf) - lenBeforeData
	be.PutUint16(buf[lenOffset:], uint16(dataLen))
	return buf
}

func appendNames(buf []byte, nc NameCompressor, names []string) []byte {
	skip, offset := nc.Lookup(names)
	nc.Record(uint16(len(buf)), names)

	for _, name := range names[:skip] {
		buf = append(buf, byte(len(name)))
		buf = append(buf, []byte(name)...)
	}

	if offset > 0 {
		buf = be.AppendUint16(buf, withCompressionFlag(offset))
	} else {
		buf = append(buf, 0)
	}

	return buf
}

func parseQuestions(buf readBuf, numQuestions uint16) ([]Question, readBuf, error) {
	if numQuestions == 0 {
		return nil, buf, nil
	}

	questions := make([]Question, numQuestions)
	for i := range numQuestions {
		var question Question
		var err error
		question, buf, err = parseQuestion(buf)
		if err != nil {
			return nil, buf, err
		}
		questions[i] = question
	}

	return questions, buf, nil
}

func parseResources(buf readBuf, count uint16) ([]Resource, readBuf, error) {
	if count == 0 {
		return nil, buf, nil
	}

	resources := make([]Resource, count)
	for i := range count {
		var resource Resource
		var err error
		resource, buf, err = parseResource(buf)
		if err != nil {
			return nil, buf, err
		}
		resources[i] = resource
	}
	return resources, buf, nil
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

func parseQuestion(buf readBuf) (Question, readBuf, error) {
	names, buf, err := parseNames(buf)
	if err != nil {
		return Question{}, buf, err
	}

	qType, _ := as[QueryType](buf.Uint16())
	qClass, err := as[QueryClass](buf.Uint16())
	if err != nil {
		return Question{}, buf, err
	}

	return Question{
		Names: names,
		Type:  qType,
		Class: qClass,
	}, buf, nil
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

type Resource struct {
	Names []string
	Type  QueryType
	Class QueryClass
	TTL   time.Duration
	Data  any
}

func parseResource(buf readBuf) (Resource, readBuf, error) {
	names, buf, err := parseNames(buf)
	if err != nil {
		return Resource{}, buf, err
	}

	qType, _ := as[QueryType](buf.Uint16())
	qClass, _ := as[QueryClass](buf.Uint16())

	ttl, _ := as[time.Duration](buf.Uint32())
	ttl = time.Second * ttl

	resourceDataLen, _ := buf.Uint16()
	resourceDataBuf := buf // copy to preserve position
	resourceDataBytes, err := buf.Slice(int(resourceDataLen))

	if err != nil {
		return Resource{}, buf, err
	}

	var resourceData any
	if qType == A && resourceDataLen == 4 {
		resourceData = net.IP(resourceDataBytes)

	} else if qType == NS {
		resourceData, _, err = parseNames(resourceDataBuf)
		if err != nil {
			return Resource{}, buf, err
		}

	} else if qType == AAAA && resourceDataLen == 16 {
		resourceData = net.IP(resourceDataBytes)

	} else if qType == MX {
		preference, _ := resourceDataBuf.Uint16()
		var names []string
		names, _, err = parseNames(resourceDataBuf)
		if err != nil {
			return Resource{}, buf, err
		}
		resourceData = MXRecord{
			Preference:   preference,
			MailExchange: names,
		}

	} else if qType == CNAME {
		resourceData, _, err = parseNames(resourceDataBuf)
		if err != nil {
			return Resource{}, buf, err
		}

	} else {
		// fallback on raw bytes
		// TODO: other types...
		resourceData = resourceDataBytes
	}

	return Resource{
		Names: names,
		Type:  qType,
		Class: qClass,
		TTL:   ttl,
		Data:  resourceData,
	}, buf, nil
}

var ErrInvalidCompression = errors.New("invalid name compression")

// maxCompressionRedirects is the maximum number of compression redirects
// we support in a single name.
//
// This is necessary, eg, to handle malicious messages that have reference
// loops that would otherwise never end.
//
// The maximum length for a name is 255 bytes, including dots, so 128
// should be more than is even possible to use.
const maxCompressionRedirects = 128

func parseNames(buf readBuf) ([]string, readBuf, error) {
	return parseNamesRec(buf, maxCompressionRedirects)
}

func parseNamesRec(buf readBuf, remainingCompressionRedirects int) ([]string, readBuf, error) {
	if remainingCompressionRedirects < 1 {
		return nil, buf, ErrInvalidCompression
	}

	var names []string
	nameLen, err := buf.Byte()
	if err != nil {
		return nil, buf, err
	}
	for nameLen > 0 {
		if isCompression(nameLen) {
			buf.BackOne()
			newOffset, err := buf.Uint16()
			if err != nil {
				return nil, buf, err
			}
			newOffset = withoutCompressionFlag(newOffset)
			pointerNames, _, err := parseNamesRec(
				buf.WithPos(int(newOffset)),
				remainingCompressionRedirects-1,
			)
			return append(names, pointerNames...), buf, err
		}

		// TODO: punycode parsing?
		name, err := buf.String(int(nameLen))
		if err != nil {
			return nil, buf, err
		}
		names = append(names, name)
		nameLen, err = buf.Byte()
		if err != nil {
			return nil, buf, err
		}
	}

	return names, buf, nil
}

const compressionMask8 = 0b1100_0000
const compressionMask16 = uint16(compressionMask8) << 8

func isCompression(len uint8) bool {
	return len&compressionMask8 == compressionMask8
}

func withoutCompressionFlag(offset uint16) uint16 {
	return offset & ^compressionMask16
}

func withCompressionFlag(offset uint16) uint16 {
	return offset | compressionMask16
}

type MXRecord struct {
	Preference   uint16
	MailExchange []string
}

type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// as allows simple numeric conversions, even in the presence
// of an error.  This simplifies, for example, converting the
// result of a function call without needing to assign a temporary
// variable.
func as[Out, In Integer](in In, err error) (Out, error) {
	return Out(in), err
}

var be = binary.BigEndian
