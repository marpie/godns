package dns

import (
	"bytes"
	"testing"
)

var (
	testDataQuestion01              = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01}
	testDataQuestionComplexComplete = []byte{0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x00, 0x00, 0x01, 0x00, 0x01}
	testDataQuestionComplexBegin    = testDataQuestionComplexComplete[15:]
	testDataQuestionGitNoteipDe     = []byte{0x03, 0x67, 0x69, 0x74, 0x06, 0x6e, 0x6f, 0x74, 0x65, 0x69, 0x70, 0x02, 0x64, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01}
)

func TestQuestionEncode(t *testing.T) {
	q, err := NewQuestion("git.noteip.de", TypeA, ClassIN)
	if err != nil {
		t.Fatal(err)
	}

	enc := q.Encode([]byte{})

	if !bytes.Equal(enc, testDataQuestionGitNoteipDe) {
		t.Fatalf("Wrong encoding expected\n\t%x but got \n\t%x", testDataQuestionGitNoteipDe, enc)
	}
}

func TestReadQuestion(t *testing.T) {
	q, err, nextIdx := ReadQuestion(testDataQuestion01, testDataQuestion01)
	if err != nil {
		t.Fatal(err)
	}

	if nextIdx == 0 {
		t.Fatalf("Next Index shouldn't be '%d'", nextIdx)
	}

	if q.Name != "noteip.de" {
		t.Fatalf("Expected 'noteip.de' got %q", q.Name)
	}

	if q.Type != TypeA {
		t.Fatalf("Expected A-Record but got %q", q.Type)
	}

	if q.Class != ClassIN {
		t.Fatalf("Expected Class-IN but got %q", q.Class)
	}
}

func TestReadQuestionComplex(t *testing.T) {
	q, err, nextIdx := ReadQuestion(testDataQuestionComplexBegin, testDataQuestionComplexComplete)
	if err != nil {
		t.Fatal(err)
	}

	if nextIdx != 6 {
		t.Fatalf("Next Index shouldn't be '%d'", nextIdx)
	}

	if q.Name != "noteip.de" {
		t.Fatalf("Expected 'noteip.de' got %q", q.Name)
	}

	if q.Type != TypeA {
		t.Fatalf("Expected A-Record but got %q", q.Type)
	}

	if q.Class != ClassIN {
		t.Fatalf("Expected Class-IN but got %q", q.Class)
	}
}
