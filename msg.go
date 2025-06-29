package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"
)

func ParseMessage(b []byte) (Message, error) {
	buf := readBuf{b, 0}

	id, _ := buf.Uint16()
	flags, _ := as[Flags](buf.Uint16())
	numQuestions, _ := buf.Uint16()
	numAnswers, _ := buf.Uint16()
	numAuthorities, _ := buf.Uint16()
	numAdditional, err := buf.Uint16()

	if err != nil {
		return Message{}, io.ErrShortBuffer
	}

	questions, buf, err := parseQuestions(buf, numQuestions)
	if err != nil {
		return Message{}, err
	}

	answers, buf, err := parseResources(buf, numAnswers)
	if err != nil {
		return Message{}, err
	}

	authorities, buf, err := parseResources(buf, numAuthorities)
	if err != nil {
		return Message{}, err
	}

	additional, buf, err := parseResources(buf, numAdditional)
	if err != nil {
		return Message{}, err
	}

	return Message{
		ID:          id,
		Flags:       flags,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additional:  additional,
	}, nil
}

func MakeResponse(qry Message) Message {
	// TODO: we should probably set a few more flags explicitly
	// eg, ResponseCode, etc
	return Message{
		ID:        qry.ID,
		Flags:     qry.Flags.WithType(Response),
		Questions: qry.Questions,
	}
}

type Message struct {
	ID          uint16
	Flags       Flags
	Questions   []Question
	Answers     []Resource
	Authorities []Resource
	Additional  []Resource
}

func (m Message) WriteTo(buf []byte) ([]byte, error) {
	buf = be.AppendUint16(buf, m.ID)
	buf = be.AppendUint16(buf, uint16(m.Flags))
	buf = be.AppendUint16(buf, uint16(len(m.Questions)))
	buf = be.AppendUint16(buf, uint16(len(m.Answers)))
	buf = be.AppendUint16(buf, uint16(len(m.Authorities)))
	buf = be.AppendUint16(buf, uint16(len(m.Additional)))

	nc := NewNameCompressor()

	for _, question := range m.Questions {
		buf = writeName(buf, nc, question.Name)

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
	buf = writeName(buf, nc, res.Name)

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
		name, ok := res.Data.(Name)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = writeVariableLengthDataToBuf(buf, func(buf []byte) []byte {
			return writeName(buf, nc, name)
		})
	case AAAA:
		buf = be.AppendUint16(buf, 16)
		ip, ok := res.Data.(net.IP)
		if !ok || ip.To16() == nil {
			return nil, errors.New("mismatched resource type")
		}
		buf = append(buf, ip.To16()...)
	case CNAME:
		name, ok := res.Data.(Name)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = writeVariableLengthDataToBuf(buf, func(buf []byte) []byte {
			return writeName(buf, nc, name)
		})
	case MX:
		mx, ok := res.Data.(MXRecord)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = writeVariableLengthDataToBuf(buf, func(buf []byte) []byte {
			buf = be.AppendUint16(buf, mx.Preference)
			return writeName(buf, nc, mx.MailExchange)
		})
	case SOA:
		soa, ok := res.Data.(SOARecord)
		if !ok {
			return nil, fmt.Errorf("mismatched resource type %s / %T",
				res.Type, res.Data)
		}
		buf = writeVariableLengthDataToBuf(buf, writeSOA(soa, nc))
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

func writeSOA(soa SOARecord, nc NameCompressor) func(buf []byte) []byte {
	return func(buf []byte) []byte {
		buf = writeName(buf, nc, soa.MName)
		buf = writeName(buf, nc, soa.RName)
		buf = be.AppendUint32(buf, soa.Serial)
		buf = be.AppendUint32(buf, uint32(soa.Refresh.Seconds()))
		buf = be.AppendUint32(buf, uint32(soa.Retry.Seconds()))
		buf = be.AppendUint32(buf, uint32(soa.Expire.Seconds()))
		buf = be.AppendUint32(buf, uint32(soa.MinTTL.Seconds()))
		return buf
	}
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

func writeName(buf []byte, nc NameCompressor, name Name) []byte {
	prefix, pointer := nc.Compress(uint16(len(buf)), name)

	for _, label := range prefix {
		// TODO: refuse to encode invalid labels?
		// - more than 64 bytes (impossible to represent)
		// - 0 bytes (subsequent labels won't be parsed)
		// - contain '.'
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}

	if pointer > 0 {
		buf = be.AppendUint16(buf, withCompressionFlag(pointer))
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

func (m Message) String() string {
	return fmt.Sprintf("DNS Message: %d, %s, %s, %t",
		m.ID,
		m.Flags.Type(),
		m.Flags.OpCode(),
		m.Flags.Authoritative(),
	)
}

//go:generate stringer -type=Type
type Type byte

const (
	Query    Type = 0
	Response Type = 1
)

//go:generate stringer -type=OpCode
type OpCode byte

const (
	StandardQuery       OpCode = 0
	InverseQuery        OpCode = 1
	ServerStatusRequest OpCode = 2
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

func (f Flags) Type() Type {
	return Type(uint16(f) >> 15)
}

func (f Flags) WithType(t Type) Flags {
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
	Name  Name
	Type  QueryType
	Class QueryClass
}

func parseQuestion(buf readBuf) (Question, readBuf, error) {
	name, buf, err := parseName(buf)
	if err != nil {
		return Question{}, buf, err
	}

	qType, _ := as[QueryType](buf.Uint16())
	qClass, err := as[QueryClass](buf.Uint16())
	if err != nil {
		return Question{}, buf, err
	}

	return Question{
		Name:  name,
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
	Name  Name
	Type  QueryType
	Class QueryClass
	TTL   time.Duration
	Data  any
}

func parseResource(buf readBuf) (Resource, readBuf, error) {
	name, buf, err := parseName(buf)
	if err != nil {
		return Resource{}, buf, err
	}

	qType, _ := as[QueryType](buf.Uint16())
	qClass, _ := as[QueryClass](buf.Uint16())

	ttl, _ := seconds(buf.Uint32())

	resourceDataLen, err := buf.Uint16()

	if err != nil {
		return Resource{}, buf, err
	}

	var resourceData any
	if qType == A && resourceDataLen == 4 || qType == AAAA && resourceDataLen == 16 {
		bytes, err := buf.Slice(int(resourceDataLen))
		if err != nil {
			return Resource{}, buf, err
		}
		resourceData = net.IP(slices.Clone(bytes))

	} else if qType == NS {
		resourceData, buf, err = parseName(buf)
		if err != nil {
			return Resource{}, buf, err
		}

	} else if qType == MX {
		preference, _ := buf.Uint16()
		var name Name
		name, buf, err = parseName(buf)
		if err != nil {
			return Resource{}, buf, err
		}
		resourceData = MXRecord{
			Preference:   preference,
			MailExchange: name,
		}

	} else if qType == CNAME {
		resourceData, buf, err = parseName(buf)
		if err != nil {
			return Resource{}, buf, err
		}

	} else if qType == SOA {
		var mName, rName Name
		mName, buf, err = parseName(buf)
		if err != nil {
			return Resource{}, buf, err
		}

		rName, buf, err = parseName(buf)
		if err != nil {
			return Resource{}, buf, err
		}

		serial, _ := buf.Uint32()
		refresh, _ := seconds(buf.Int32())
		retry, _ := seconds(buf.Int32())
		expire, _ := seconds(buf.Int32())
		minTTL, err := seconds(buf.Uint32())

		if err != nil {
			return Resource{}, buf, err
		}

		resourceData = SOARecord{
			MName:   mName,
			RName:   rName,
			Serial:  serial,
			Refresh: refresh,
			Retry:   retry,
			Expire:  expire,
			MinTTL:  minTTL,
		}

	} else {
		// fallback on raw bytes
		// TODO: other types...
		bytes, err := buf.Slice(int(resourceDataLen))
		if err != nil {
			return Resource{}, buf, err
		}
		resourceData = slices.Clone(bytes)
	}

	return Resource{
		Name:  name,
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

func parseName(buf readBuf) (Name, readBuf, error) {
	// pre-allocate a reasonable number of spaces to avoid re-allocation as
	// we discover more of the name:
	name := make(Name, 0, 4)
	return parseNameRec(buf, name, maxCompressionRedirects)
}

func parseNameRec(buf readBuf, name Name, remainingCompressionRedirects int) (Name, readBuf, error) {
	if remainingCompressionRedirects < 1 {
		return nil, buf, ErrInvalidCompression
	}

	labelLen, err := buf.Byte()
	if err != nil {
		return nil, buf, err
	}
	for labelLen > 0 {
		if isCompression(labelLen) {
			buf.BackOne()
			newOffset, err := buf.Uint16()
			if err != nil {
				return nil, buf, err
			}
			newOffset = withoutCompressionFlag(newOffset)
			name, _, err := parseNameRec(
				buf.WithPos(int(newOffset)),
				name,
				remainingCompressionRedirects-1,
			)
			return name, buf, err
		}

		// TODO: punycode parsing?
		label, err := buf.String(int(labelLen))
		if err != nil {
			return nil, buf, err
		}
		name = append(name, Label(label))
		labelLen, err = buf.Byte()
		if err != nil {
			return nil, buf, err
		}
	}

	return name, buf, nil
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
	MailExchange Name
}

func (mx MXRecord) String() string {
	return fmt.Sprintf("%d %s", mx.Preference, mx.MailExchange)
}

type SOARecord struct {
	MName  Name
	RName  Name
	Serial uint32

	// NB: not all duration values can be represented
	// on the wire in DNS:

	Refresh time.Duration
	Retry   time.Duration
	Expire  time.Duration
	MinTTL  time.Duration
}

func (s SOARecord) String() string {
	return fmt.Sprintf("%s %s %d %s %s %s %s",
		s.MName, s.RName, s.Serial,
		s.Refresh, s.Retry, s.Expire, s.MinTTL,
	)
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

// seconds converts an integer type to a duration in seconds
// even in the presence of an error.
func seconds[In Integer](in In, err error) (time.Duration, error) {
	d, err := as[time.Duration](in, err)
	return d * time.Second, err
}

var be = binary.BigEndian
