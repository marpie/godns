package dns

import (
	"bytes"
	"testing"
)

var (
	testDataMessageAnswer01 = []byte{0x88, 0x5a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x67, 0x69, 0x74, 0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x13, 0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x06, 0x64, 0x79, 0x6e, 0x64, 0x6e, 0x73, 0x03, 0x6f, 0x72, 0x67, 0x00, 0xc0, 0x2b, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x54, 0xb7, 0x74, 0x63}
)

func TestMessageEncode(t *testing.T) {
	msg, _ := ReadMessage(testDataMessageAnswer01)

	enc := msg.Encode()

	if !bytes.Equal(enc, testDataMessageAnswer01) {
		t.Fatalf("Wrong wire format expected\n\t%x\n\t%x", testDataMessageAnswer01, enc)
	}
}

func TestReadMessage01(t *testing.T) {
	msg, err := ReadMessage(testDataMessageAnswer01)
	if err != nil {
		t.Fatal(err)
	}

	if msg.Header.QuestionCount != 1 {
		t.Fatalf("QuestionCount should be 1 but got %d", msg.Header.QuestionCount)
	}

	if len(msg.Answer) < 2 {
		t.Fatalf("len(msg.Answer) should be '2' but got '%d'", len(msg.Answer))
	}

	if msg.Answer[0].Name != "git.noteip.de" {
		t.Fatalf("Answer[0].Name should be 'noteip.de' but got %q", msg.Answer[0].Name)
	}

	if msg.Answer[0].TTL != 0x15180 {
		t.Fatalf("Answer[0].TTL should be 8400 but got %q", msg.Answer[0].TTL)
	}

	if msg.Answer[1].Name != "noteip.dyndns.org" {
		t.Fatalf("Answer[1].Name should be 'noteip.dyndns.org' but got %q", msg.Answer[1].Name)
	}
}

func BenchmarkReadMessage01(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := ReadMessage(testDataMessageAnswer01)
		if err != nil {
			b.Fatal(err)
		}
	}
}
