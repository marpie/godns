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
