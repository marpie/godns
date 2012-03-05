package dns

import (
	"testing"
)

var (
	testDataNoteipDe   = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00}
	testDataNoteipDeDe = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x02, 0x64, 0x65, 0x00}
	testDataInvalid    = []byte{0x04, 0x6e, 0x00}
)

func TestEncode(t *testing.T) {
	dns := DNSName("noteip.de")
	b, err := dns.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if len(b) == 0 {
		t.Fatal("Empty result.")
	}

	if str, _ := DecodeDNSName(b); str != dns {
		t.Fatalf("Convertion failed! Expected '%q' got '%q'", dns, str)
	}
}

func TestDecode(t *testing.T) {
	if dns, err := DecodeDNSName(testDataNoteipDe); err != nil || dns != "noteip.de" {
		t.Fatalf("DNSName should be 'noteip.de' but got '%q'", dns)
	}

	if dns, err := DecodeDNSName(testDataNoteipDeDe); err != nil || dns != "noteip.de.de" {
		t.Fatalf("DNSName should be 'noteip.de.de' but got '%q'", dns)
	}

	if dns, err := DecodeDNSName(testDataInvalid); err != ErrInvalidFormat || dns != "" {
		t.Fatalf("DNSName should be invalid! -> %s", err)
	}
}
