package dns

// Message implements the overall message format of the DNS specification.
// All messages sent by the domain system are divided into 5 sections (some
// of which are empty in certain cases).
type Message struct {
	// The header section is always present.
	Header *Header

	// The question section contains fields that describe a question to a
	// name server.
	Question []*Question

	// The last three sections have the same format!

	// The answer section contains resource records (RRs) that answer the
	// question.
	Answer []*ResourceRecord

	// The authority section contains RRs that point toward an authoritative
	// name server.
	Authority []*ResourceRecord

	// The additional records section contains RRs which relate to the query,
	// but are not strictly answers for the question.
	Additional []*ResourceRecord
}

func (msg *Message) Encode() []byte {
	// Encode Header
	buf := msg.Header.Encode()

	// Encode Questions
	for _, q := range msg.Question {
		buf = q.Encode(buf)
	}

	// Encode Answers
	for _, a := range msg.Answer {
		buf = a.Encode(buf)
	}

	// Encode Authority
	for _, a := range msg.Authority {
		buf = a.Encode(buf)
	}

	// Encode Additional
	for _, a := range msg.Additional {
		buf = a.Encode(buf)
	}

	return buf
}

func NewMessage() (msg *Message, err error) {
	msg = new(Message)

	msg.Header, err = NewHeader()
	if err != nil {
		return nil, err
	}

	return nil, ErrNotImplemented
}

func NewQuery(domainName string, queryType uint16, queryClass uint16) (msg *Message, err error) {
	msg, err = NewMessage()

	msg.Header.SetQuery(true)
	msg.Header.SetRecursionDesired(true)
	msg.Header.SetOpcode(OpcodeQuery)

	q, err := NewQuestion(domainName, queryType, queryClass)
	if err != nil {
		return nil, err
	}
	msg.Question = append(msg.Question, q)
	msg.Header.QuestionCount += 1

	return msg, nil
}

// ReadMessage parses a message from b.
func ReadMessage(b []byte) (msg *Message, err error) {
	msg = new(Message)

	msg.Header, err = ReadHeader(b)
	if err != nil {
		return nil, err
	}
	nextPos := 12

	for i := 0; i < int(msg.Header.QuestionCount); i++ {
		q, err, nextIdx := ReadQuestion(b[nextPos:], b)
		if err != nil {
			return nil, err
		}
		nextPos += nextIdx
		msg.Question = append(msg.Question, q)
	}

	for i := 0; i < int(msg.Header.AnswerCount); i++ {
		rr, err, nextIdx := ReadResourceRecord(b[nextPos:], b)
		if err != nil {
			return nil, err
		}
		nextPos += nextIdx
		msg.Answer = append(msg.Answer, rr)
	}

	for i := 0; i < int(msg.Header.AuthorityCount); i++ {
		rr, err, nextIdx := ReadResourceRecord(b[nextPos:], b)
		if err != nil {
			return nil, err
		}
		nextPos += nextIdx
		msg.Authority = append(msg.Authority, rr)
	}

	for i := 0; i < int(msg.Header.AdditionalCount); i++ {
		rr, err, nextIdx := ReadResourceRecord(b[nextPos:], b)
		if err != nil {
			return nil, err
		}
		nextPos += nextIdx
		msg.Additional = append(msg.Additional, rr)
	}

	return msg, nil
}
