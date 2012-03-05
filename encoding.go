package dns

import (
	"bytes"
	"strings"
)

type DNSName string

// Encode converts a string to the DNS Name Notation format.
func (name *DNSName) Encode() (b []byte, err error) {
	var buf bytes.Buffer

	parts := strings.Split(string(*name), ".")
	for i := 0; i < len(parts); i++ {
		err := buf.WriteByte(byte(len(parts[i])))
		if err != nil {
			return nil, err
		}
		_, err = buf.WriteString(parts[i])
		if err != nil {
			return nil, err
		}
	}
	err = buf.WriteByte(0x00)

	return buf.Bytes(), nil
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
