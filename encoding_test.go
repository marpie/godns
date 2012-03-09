package dns

import (
	"bytes"
	"testing"
)

var (
	testDataComplex    = []byte{0x03, 0x77, 0x77, 0x77, 0xC0, 0x06, 0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00}
	testDataNoteipDe   = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00}
	testDataNoteipDeDe = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x02, 0x64, 0x65, 0x00}
	testDataEncode02   = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00, 0x03, 0x67, 0x69, 0x74, 0xc0, 0x00}
	testDataInvalid    = []byte{0x04, 0x6e, 0x00}
	testDataNull       = []byte{0x00}
)

func TestDNSNameEncode01(t *testing.T) {
	dns := DNSName("noteip.de")
	enc := dns.Encode([]byte{})

	if len(enc) == 0 {
		t.Fatal("Empty result.")
	}

	if !bytes.Equal(enc, testDataNoteipDe) {
		t.Fatalf("Convertion failed! Expected '%x' got '%x'", testDataNoteipDe, enc)
	}
}

func TestDNSNameEncode02(t *testing.T) {
	dns := DNSName("noteip.de")
	enc := dns.Encode([]byte{})

	dns = DNSName("git.noteip.de")
	enc2 := dns.Encode(enc)

	if len(enc2) == 0 {
		t.Fatal("Empty result.")
	}

	if !bytes.Equal(enc2, testDataEncode02) {
		t.Fatalf("Convertion failed! \n\tExpected \n\t\t'%x' \n\tgot \n\t\t'%x'", testDataEncode02, enc2)
	}
}

func TestDNSNameDecode01(t *testing.T) {
	if dns, err, num := DecodeDNSName(testDataNoteipDe, testDataNull); err != nil || dns != "noteip.de" || num != 11 {
		t.Fatalf("DNSName should be 'noteip.de' but got '%q'. Next Index = %d.", dns, num)
	}
}

func TestDNSNameDecode02(t *testing.T) {
	if dns, err, num := DecodeDNSName(testDataNoteipDeDe, testDataNull); err != nil || dns != "noteip.de.de" || num != 14 {
		t.Fatalf("DNSName should be 'noteip.de.de' but got '%q'. Next Index = %d.", dns, num)
	}
}

func TestDNSNameDecode03(t *testing.T) {
	if dns, err, _ := DecodeDNSName(testDataInvalid, testDataNull); err != ErrInvalidFormat || dns != "" {
		t.Fatalf("DNSName should be invalid! -> %s", err)
	}
}

func TestDNSNameDecodeComplex(t *testing.T) {
	if dns, _, num := DecodeDNSName(testDataComplex, testDataComplex); dns != "www.noteip.de" || num != 6 {
		t.Fatalf("Expected 'www.noteip.de' but got '%s'. Next Index = %d.", dns, num)
	}
}
