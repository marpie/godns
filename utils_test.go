package dns

import (
	"testing"
)

func TestByteToInt16(t *testing.T) {
	buf := []byte("Hello World!")

	if byteToInt16(buf) != 0x4865 {
		t.Fatalf("Wrong Result, expected '%X' got '%X'", 0x4865, byteToInt16(buf))
	}
}

func TestByteToUint16(t *testing.T) {
	buf := []byte("Hello World!")

	if byteToUint16(buf) != 0x4865 {
		t.Fatalf("Wrong Result, expected '%X' got '%X'", 0x4865, byteToUint16(buf))
	}
}

func TestUint16ToByte(t *testing.T) {
	buf := make([]byte, 2)
	uint16ToByte(0x4865, buf)
	if buf[0] != 0x48 || buf[1] != 0x65 {
		t.Fatalf("Wrong value: 0x%x%x", buf[0], buf[1])
	}
}
