package dns

const (
	_ = iota
	// A host address
	QuestionTypeA
	// An authoritative name server
	QuestionTypeNS
	// A mail destination
	QuestionTypeMD
	// A mail forwarder
	QuestionTypeMF
	// The canonical name for an alias
	QuestionTypeCNAME
	// Marks the start of a zone of authority
	QuestionTypeSOA
	// A mailbox domain name
	QuestionTypeMB
	// A mail group member
	QuestionTypeMG
	// A mail rename domain name
	QuestionTypeMR
	// A null RR
	QuestionTypeNULL
	// A well known service description
	QuestionTypeWKS
	// A domain name pointer
	QuestionTypePTR
	// Host information
	QuestionTypeHINFO
	// Mailbox or mail list information
	QuestionTypeMINFO

	// A request for a transfer of an entire zone of authority
	QuestionTypeAXFR = 252
	// A request for mailbox-related records (MB, MG or MR)
	QuestionTypeMAILB = 253
	// A request for mail agent RRs (MD and MF)
	QuestionTypeMAILA = 254
	// A request for all records
	QuestionTypeAll = 255
)

const (
	// The ARPA Internet
	QuestionClassIN = 1
	// The computer science network (CSNET)
	QuestionClassCS = 2
	// Any class
	QuestionClassAny = 255
)

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
