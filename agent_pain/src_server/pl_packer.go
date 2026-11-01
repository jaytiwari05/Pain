package main

import "encoding/binary"

// Defining the key
const XOR_KEY uint64 = 0xDEADBEEFCAFEBABE

// Just a simple XOR Encryption
func XorCrypt(data []byte) []byte {
	var key [8]byte
	binary.LittleEndian.PutUint64(key[:], XOR_KEY)

	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%8]
	}
	return out
}

// XorCryptWithKey XORs data with an arbitrary-length repeating key.
// Used for auth-mode sessions where SessionKey is the raw 16-byte auth key.
func XorCryptWithKey(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return XorCrypt(data)
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// this is the Go-side mirror of Pain's PARSER struct in Parser.cc
type Parser struct {
	buf []byte
}

// NewParser wraps a raw byte slice so we can read from it field by field
func NewParser(data []byte) *Parser {
	return &Parser{buf: data}
}

// Remaining tells us how many bytes are left unread
func (p *Parser) Remaining() int {
	return len(p.buf)
}

// Reads the 4 bytes big-endian from Package.cc
func (p *Parser) ReadInt32() uint32 {
	if len(p.buf) < 4 {
		return 0
	}
	v := binary.BigEndian.Uint32(p.buf[:4])
	p.buf = p.buf[4:] // advance cursor past the 4 bytes we just consumed
	return v
}

// ReadPad reads exactly n raw bytes with NO length prefix.
func (p *Parser) ReadPad(n int) []byte {
	if len(p.buf) < n {
		return nil
	}
	b := make([]byte, n)
	copy(b, p.buf[:n])
	p.buf = p.buf[n:]
	return b
}

// ReadBytes reads a length-prefixed blob: [4-byte BE size][data].
func (p *Parser) ReadBytes() []byte {
	size := int(p.ReadInt32())
	if len(p.buf) < size {
		return nil
	}
	b := make([]byte, size)
	copy(b, p.buf[:size])
	p.buf = p.buf[size:] // advance cursor past the data
	return b
}

// Packer builds a byte slice by appending fields one at a time
type Packer struct {
	buf []byte
}

// NewPacker creates an empty pakcer ready to receive fileds
func NewPacker() *Packer {
	return &Packer{}
}

// WriteInt32 appends 4 bytes big-endian
func (p *Packer) WriteInt32(v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b ,v)
	p.buf = append(p.buf, b...)
}

// WritePad appends raw bytes with NO Length prefix
func (p *Packer) WritePad(data []byte) {
	p.buf = append(p.buf, data...)
}

// WriteBytes appends [4-byte BE length] [data]
// Matches Psr_Bytes in Pain's Parser.cc which reads length first, then data
func (p *Packer) WriteBytes(data []byte) {
	p.WriteInt32(uint32(len(data)))
	p.buf = append(p.buf, data...)
}

// WriteStr is WriteBytes but takes a string directly
func (p *Packer) WriteStr(s string) {
	p.WriteBytes([]byte(s))
}

// Bytes returns the final byte slice ready to send
func (p *Packer) Bytes() []byte {
	return p.buf
}
