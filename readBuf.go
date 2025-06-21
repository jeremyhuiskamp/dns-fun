package dns

import "io"

// readBuf provides operations for reading through a buffer.
//
// Any read operation will advance the position, whether there is
// enough space or not.  This ensures that future reads will fail, making
// it easy to do a series of reads and only check for an error on the
// last one.
type readBuf struct {
	buf []byte
	pos int
}

func (b readBuf) WithPos(pos int) readBuf {
	b.pos = pos
	return b
}

func (b *readBuf) Byte() (byte, error) {
	p, ok := b.move(1)
	if !ok {
		return 0, io.ErrShortBuffer
	}
	return b.buf[p], nil
}

// BackOne moves backwards by one byte, if possible.
func (b *readBuf) BackOne() {
	if b.pos > 0 {
		b.pos--
	}
}

func (b *readBuf) Uint16() (uint16, error) {
	p, ok := b.move(2)
	if !ok {
		return 0, io.ErrShortBuffer
	}
	return be.Uint16(b.buf[p:]), nil
}

func (b *readBuf) Uint32() (uint32, error) {
	p, ok := b.move(4)
	if !ok {
		return 0, io.ErrShortBuffer
	}
	return be.Uint32(b.buf[p:]), nil
}

func (b *readBuf) Int32() (int32, error) {
	u, err := b.Uint32()
	return int32(u), err
}

func (b *readBuf) Slice(size int) ([]byte, error) {
	p, ok := b.move(size)
	if !ok {
		return nil, io.ErrShortBuffer
	}
	return b.buf[p:b.pos], nil
}

func (b *readBuf) String(size int) (string, error) {
	bytes, err := b.Slice(size)
	return string(bytes), err
}

func (b *readBuf) move(size int) (int, bool) {
	p := b.pos
	b.pos += size
	return p, len(b.buf) >= b.pos
}
