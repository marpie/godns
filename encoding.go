package dns

import (
	"bytes"
	"strings"
)

type DNSName string

// Encode converts a string to the DNS Name Notation format.
func (name *DNSName) Encode(rawMsg []byte) (newRaw []byte) {
	var buf bytes.Buffer

	// prepare wire format
	tmpName := []byte(*name)
	parts := strings.Split(string(*name), ".")
	wireName := make([]byte, len(tmpName)+1)
	pos := 0
	for i := 0; i < len(parts); i++ {
		copy(wireName[pos:], []byte{byte(len(parts[i]))})
		copy(wireName[pos+1:], parts[i])

		pos += len(parts[i]) + 1
	}

	for {
		if idx := bytes.Index(rawMsg, wireName); idx == -1 || idx >= 0xFF3F {
			// wireName not found or idx too big to encode.

			// search next "."
			sepIdx := bytes.Index(tmpName, []byte{0x2E})

			if sepIdx > -1 {
				// Write string length and string
				buf.Write(wireName[:sepIdx+1])
			} else {
				buf.Write(wireName[:])
				// If no "." is found the encoding is done.
				buf.WriteByte(0x00)
				break
			}

			wireName = wireName[sepIdx+1:]
			tmpName = tmpName[sepIdx+1:]
		} else {
			// String found calculate location.
			loc := uint16(0xC000 + idx)
			buf.WriteByte(byte(loc >> 8))
			buf.WriteByte(byte(loc))
			break
		}
	}

	return append(rawMsg, buf.Bytes()...)
}

// DecodeDNSName converts the DNS Name Notation to a string.
// nextIdx specifies the position of the following element.
func DecodeDNSName(b []byte, rawMsg []byte) (name DNSName, err error, nextIdx int) {
	var dnsStr string

	i := 0
	for i < len(b) {
		l := int(b[i])
		if l >= 0xC0 {
			// DNS Compression used.
			l := byteToUint16(b[i:]) ^ 0xC000
			tmpName, err, _ := DecodeDNSName(rawMsg[l:], rawMsg)
			if err != nil {
				return "", err, 0
			}
			dnsStr += "." + string(tmpName)
			i += 1
			break
		} else {
			next := i + l + 1
			if l == 0 {
				break
			} else if next >= len(b) {
				return "", ErrInvalidFormat, 0
			}
			dnsStr += "." + string(b[i+1:next])
			i = next
		}
	}

	return DNSName(dnsStr[1:]), nil, i + 1
}
