package dns

// Question implements the DNS question field. The question section contains
// fields that describe a question to a name server. These fields are a query
// type (QTYPE), a query class (QCLASS) and a query domain name (QNAME).
// The question section is used in all kinds of queries other than inverse
// queries. In responses to inverse queries this section may contain multiple
// entries; for all other responses it contains a single entry.
type Question struct {
	Name  DNSName
	Type  uint16
	Class uint16
}

// ReadQuestion parses the question part of the received message. b is the
// start of the question part and rawMessage is the whole message.
func ReadQuestion(b []byte, rawMessage []byte) (q *Question, err error, nextIdx int) {
	q = new(Question)

	q.Name, err, nextIdx = DecodeDNSName(b, rawMessage)

	if err != nil {
		return nil, err, 0
	}
	if len(b) < nextIdx+4 {
		return nil, ErrInvalidFormat, 0
	}
	q.Type = byteToUint16(b[nextIdx : nextIdx+2])
	q.Class = byteToUint16(b[nextIdx+2 : nextIdx+4])
	nextIdx += 4

	return
}
