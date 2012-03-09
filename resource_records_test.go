package dns

import (
	"bytes"
	"testing"
)

var (
	testDataRR01          = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x04, 0x58, 0xc6, 0x12, 0xc9}
	testDataRRBegin       = testDataRR01[15:]
	testDataRRGitNoteipDe = []byte{0x03, 0x67, 0x69, 0x74, 0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x13, 0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x06, 0x64, 0x79, 0x6e, 0x64, 0x6e, 0x73, 0x03, 0x6f, 0x72, 0x67, 0x00}
)

func TestResourceRecordEncode(t *testing.T) {
	rr, err, _ := ReadResourceRecord(testDataRRGitNoteipDe, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	enc := rr.Encode([]byte{})

	if !bytes.Equal(enc, testDataRRGitNoteipDe) {
		t.Fatalf("Wrong encoding expected\n%x\n%x", testDataRRGitNoteipDe, enc)
	}
}

func TestReadResourceRecord(t *testing.T) {
	rr, err, nextIdx := ReadResourceRecord(testDataRRBegin, testDataRR01)

	if err != nil {
		t.Fatal(err)
	}

	if nextIdx == 0 {
		t.Fatal("NextIdx shouldn't be 0")
	}

	if rr.Name != "noteip.de" {
		t.Fatalf("Expected 'noteip.de' but got %q", rr.Name)
	}

	if rr.Type != TypeA {
		t.Fatalf("Expected Type-A got %q", rr.Type)
	}

	if rr.Class != ClassIN {
		t.Fatalf("Expected Class-IN got %q", rr.Class)
	}

	if rr.TTL != 0x15180 {
		t.Fatalf("TTL should be 86400 got %q", rr.TTL)
	}

	if rr.Length != 4 {
		t.Fatalf("Data Length should be 4 but got %q", rr.Length)
	}
}
