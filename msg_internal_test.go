package dns

import (
	"math"
	"testing"
	"time"
)

func TestUnsignedDuration(t *testing.T) {
	for _, input := range []uint32{
		0,
		math.MaxUint32,
	} {
		soa := SOARecord{
			MinTTL: time.Duration(input) * time.Second,
		}
		buf := writeSOA(soa, NewNameCompressor())(nil)
		buf = buf[len(buf)-4:]

		// simple check:
		readVal := be.Uint32(buf)
		if readVal != input {
			t.Errorf("read %d, expected %d", readVal, input)
		}

		// also test seconds():
		rbuf := readBuf{buf: buf}
		readDuration, err := seconds(rbuf.Uint32())
		if err != nil {
			t.Errorf("unexpected error while reading %d: %s", input, err)
		} else if readDuration != soa.MinTTL {
			t.Errorf("read %s, expected %s", readDuration, soa.MinTTL)
		}
	}
}

func TestSignedDuration(t *testing.T) {
	for _, input := range []int32{
		0,
		-1,
		math.MaxInt32,
		math.MinInt32,
	} {
		soa := SOARecord{
			Expire: time.Duration(input) * time.Second,
		}
		buf := writeSOA(soa, NewNameCompressor())(nil)
		buf = buf[len(buf)-8:][:4]

		// simple check:
		readVal := int32(be.Uint32(buf))
		if readVal != input {
			t.Errorf("read %d, expected %d", readVal, input)
		}

		// also test seconds():
		rbuf := readBuf{buf: buf}
		readDuration, err := seconds(rbuf.Int32())
		if err != nil {
			t.Errorf("unexpected error while reading %d: %s", input, err)
		} else if readDuration != soa.Expire {
			t.Errorf("read %s, expected %s", readDuration, soa.MinTTL)
		}
	}
}

// NB: time.Duration can represent more values than dns can with
// either signed or unsigned 32-bit numbers.
// Not testing for unrepresentable values here, we'll just
// assume we produce garbage...
