package dns

const (
	_ = iota
	// A host address
	TypeA
	// An authoritative name server
	TypeNS
	// A mail destination
	TypeMD
	// A mail forwarder
	TypeMF
	// The canonical name for an alias
	TypeCNAME
	// Marks the start of a zone of authority
	TypeSOA
	// A mailbox domain name
	TypeMB
	// A mail group member
	TypeMG
	// A mail rename domain name
	TypeMR
	// A null RR
	TypeNULL
	// A well known service description
	TypeWKS
	// A domain name pointer
	TypePTR
	// Host information
	TypeHINFO
	// Mailbox or mail list information
	TypeMINFO

	// A request for a transfer of an entire zone of authority
	TypeAXFR = 252
	// A request for mailbox-related records (MB, MG or MR)
	TypeMAILB = 253
	// A request for mail agent RRs (MD and MF)
	TypeMAILA = 254
	// A request for all records
	TypeAll = 255
)

const (
	// The ARPA Internet
	ClassIN = 1
	// The computer science network (CSNET)
	ClassCS = 2
	// Any class
	ClassAny = 255
)
