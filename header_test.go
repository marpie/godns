package dns

import (
	"testing"
)

var (
	testHeaderQuery    = []byte{0x91, 0xcc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	testHeaderResponse = []byte{0x91, 0xcc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
)

func setUp(b []byte) (*Header, error) {
	hdr, err := ReadHeader(b)

	return hdr, err
}

func TestNewHeader(t *testing.T) {
	_, err := NewHeader()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadHeader(t *testing.T) {
	_, err := setUp(testHeaderQuery)
	if err != nil {
		t.Fatalf("%q", err)
	}

	hdr, err := setUp(testHeaderResponse)
	if err != nil {
		t.Fatalf("%q", err)
	}

	if hdr.Id != 0x91cc {
		t.Fatalf("ID should be '0x91cc' but got '0x%x'", hdr.Id)
	}
}

func TestFlagOpcode(t *testing.T) {
	var hdr Header
	hdr.Flags = 0xA800

	if hdr.Opcode() != OpcodeUpdate {
		t.Logf("\n%b\n%b", hdr.Flags, hdr.Opcode())
		t.Fatalf("Should be a standard query but got '%d'", hdr.Opcode())
	}

	hdr.Flags = 0x6800
	if hdr.Opcode() != 0xD {
		t.Logf("\n%b\n%b", hdr.Flags, hdr.Opcode())
		t.Fatal("Shift seems to be off!")
	}
}

func TestFlagAuthoritativeAnswer(t *testing.T) {
	var hdr Header
	hdr.Flags = 0x400

	if !hdr.IsAuthoritativeAnswer() {
		t.Logf("\n%b\n%b", hdr.Flags, flagAuthoritativeAnswer)
		t.Fatal("Should be authoritative.")
	}
}

func TestFlagTruncation(t *testing.T) {
	var hdr Header
	hdr.Flags = 0x200

	if !hdr.IsTruncated() {
		t.Logf("\n%b\n%b", hdr.Flags, flagTruncation)
		t.Fatal("Should be truncated.")
	}
}

func TestFlagRecursionDesired(t *testing.T) {
	var hdr Header
	hdr.Flags = 0x280

	if hdr.IsRecursionDesired() {
		t.Logf("\n%b\n%b", hdr.Flags, flagRecursionDesired)
		t.Fatal("Recursion shouldn't be desired.")
	}
}

func TestFlagResponseCode(t *testing.T) {
	var hdr Header
	hdr.Flags = 0xA

	if hdr.ResponseCode() != 0xA {
		t.Fatal("Response code should be 10.")
	}

	hdr.Flags = 0xFA

	if hdr.ResponseCode() != 0xA {
		t.Fatal("Response code should be 10.")
	}
}

func TestFlags(t *testing.T) {
	// Test Query
	hdr, _ := setUp(testHeaderQuery)

	if !hdr.IsQuery() {
		t.Logf("\n%b\n%b", hdr.Flags, flagRecursionDesired)
		t.Fatal("Message should be a query but seems to be a response!")
	}

	if hdr.Opcode() != OpcodeQuery {
		t.Fatalf("Should be a standard query but got '%d'", hdr.Opcode())
	}

	if hdr.IsAuthoritativeAnswer() {
		t.Fatal("Shouldn't be authoritative!")
	}

	if hdr.IsTruncated() {
		t.Fatal("Shouldn't be truncated!")
	}

	if !hdr.IsRecursionDesired() {
		t.Fatal("Recursion should be desired!")
	}

	if hdr.IsRecursionAvailable() {
		t.Fatal("Recursion shouldn't be available!")
	}

	if hdr.ResponseCode() != RCodeNoError {
		t.Fatal("ResponseCode should be 'No Error (0)'")
	}

	// Test Response
	hdr, _ = setUp(testHeaderResponse)

	if !hdr.IsResponse() {
		t.Fatal("Message should be a response but seems to be a query!")
	}

	if hdr.Opcode() != OpcodeQuery {
		t.Fatalf("Should be a standard query but got '%d'", hdr.Opcode())
	}

	if hdr.IsAuthoritativeAnswer() {
		t.Fatal("Shouldn't be a authoritative answer!")
	}

	if hdr.IsTruncated() {
		t.Fatal("Shouldn't be truncated!")
	}

	if !hdr.IsRecursionDesired() {
		t.Fatal("Recursion should be desired!")
	}

	if !hdr.IsRecursionAvailable() {
		t.Fatal("Recursion should be available!")
	}

	if hdr.ResponseCode() != RCodeNoError {
		t.Fatal("ResponseCode should be 'No Error (0)'")
	}
}
