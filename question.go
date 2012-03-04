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
	ClassTypeIN = 1
	// The computer science network (CSNET)
	ClassTypeCS = 2
	// Any class
	ClassTypeAny = 255
)

// Question implements the DNS question field. The question section contains
// fields that describe a question to a name server. These fields are a query
// type (QTYPE), a query class (QCLASS) and a query domain name (QNAME).
// The question section is used in all kinds of queries other than inverse
// queries. In responses to inverse queries this section may contain multiple
// entries; for all other responses it contains a single entry.
type Question struct {
	Name string
	// 
	Type  uint16
	Class uint16
}
