package dns

import (
  "bufio"
  "errors"
)

var (
  ErrNotImplemented = errors.New("Not Implemented.")
)

// Message implements the overall message format of the DNS Specification.
// All messages sent by the domain system are divided into 5 sections (some
// of which are empty in certain cases).
type Message struct {
  // The header section is always present.
  Header Header

  // The question section contains fields that describe a question to a
  // name server.
  Question Question

  // The last three sections have the same format!

  // The answer section contains resource records (RRs) that answer the
  // question.
  Answer []ResourceRecords

  // The authority section contains RRs that point toward an authoritative
  // name server.
  Authority []ResourceRecords

  // The additional records section contains RRs which relate to the query,
  // but are not strictly answers for the question.
  Additional []ResourceRecords
}

func NewMessage() (*Message, error) {
  return nil, ErrNotImplemented
}

func ReadMessage(b *bufio.Reader) (msg *Message, err error) {
  return nil, ErrNotImplemented
}

