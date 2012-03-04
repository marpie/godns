package dns

import (
	"bytes"
	"errors"
	"strings"
)

var (
	ErrInvalidFormat = errors.New("Invalid File Format.")
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
func DecodeDNSName(b []byte) (DNSName, error) {
	var dnsStr string
	i := 0
	for i < len(b) {
		l := int(b[i])
		next := i + l + 1
		if l == 0 {
			break
		} else if next >= len(b) {
			return "", ErrInvalidFormat
		}
		dnsStr += "." + string(b[i+1:next])
		i = next
	}

	return DNSName(dnsStr[1:]), nil
}
