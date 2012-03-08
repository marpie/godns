package dns

import (
	"crypto/rand"
	"math/big"
)

const (
	flagQueryResponse         = uint16(1 << 15)
	flagOperationCodePosition = 12
	flagAuthoritativeAnswer   = uint16(1 << 10)
	flagTruncation            = uint16(1 << 9)
	flagRecursionDesired      = uint16(1 << 8)
	flagRecursionAvailable    = uint16(1 << 7)
	flagResponseCodeBits      = 4
	flagResponseCodePosition  = 0
)

const (
	// A standard query
	OpcodeQuery = 0
	// An inverse query; now obsolete. RFC 1035 defines the inverse query
	// as an optional method for performing inverse DNS lookups, that is,
	// finding a name from an IP address. Due to implementation difficulties,
	// the method was never widely deployed, however, in favor of reverse 
	// mapping using IN-ADDR.ARPA domain. Use of this Opcode value was formally
	// obsoleted in RFC 3425 (Nov 2002).
	OpcodeInverseQuery = 1

	// A server status request.
	OpcodeStatus = 2

	// Opcode 3 is reserved and not used!

	// A special message type added by RFC 1996. It is used by a primary
	// (master, authoritative) server to tell secondary servers that data
	// for a zone has changed and prompt them to request a zone transfer.
	OpcodeNotify = 4

	// A special message type added by RFC 2136 to implement "dynamic DNS".
	// It allows resource records to be added, deleted or updated selectively.
	OpcodeUpdate = 5
)

const (
	// No error occured.
	RCodeNoError = iota

	// The server was unable to respond to the query due to a problem with
	// how it was constructed.
	RCodeFormatError

	// The server was unable to respond to the query due to a problem with
	// the server itself.
	RCodeServerFailure

	// The name specified in the query does not exist in the domain. This
	// code can be used by an authoritative server for a zone (since it 
	// knows all the objects and subdomains in a domain) or by a chaching
	// server that implements negative caching.
	RCodeNameError

	// The type of query received is not supported by the server.
	RCodeNotImplemented

	// The server refused to process the query, generally for policy reasons
	// and not technical ones. For example, certain Types of operations, such
	// zone transfers, are restricted. The server will honor a zone transfer
	// request only from certain devices.
	RCodeRefused

	// A name esists when it should not.
	RCodeYXDomain

	// A resource record set exists that should not.
	RCodeYXRRSet

	// A resource record set that should exist does not.
	RCodeNXRRSet

	// The server receiving the query is not authoritative for the zone 
	// specified.
	RCodeNotAuth

	// A name specified in the message is not within the zone specified
	// in the message.
	RCodeNotZone
)

// Header implements the DNS Header field and is always present in a Message.
// The header includes fields that specify which of the remaining sections
// are present, and also specify whether the message is a query, inverse 
// query, completion query or response.
type Header struct {
	// ID is a identifier assigned by the program that generates any kind of 
	// query. This identifier is copied into all replies and can be used by the
	// requestor to relate replies to outstanding questions.
	Id uint16

	// Flags contains 7 bit fields:
	//   QR      - A one bit field that specifies whether this message is a
	//             query (0) or a response (1).
	//   OPCODE  - A four bit field that specifies the kind of query in this
	//             message. This value is set by the originator of a query
	//             and copied into the response.
	//   AA      - Authoritative Answer - this bit is valid in responses,
	//                      and specifies that the responding name server
	//                      is an authority for the domain name in the 
	//                      corresponding query.
	//   TC      - Truncation - specifies that this message was truncated
	//                      due to length greater than 512 characters.
	//                      This bit is valid in datagra messages (UDP but
	//                      not in messages sent over virtual circuits (TCP).
	//   RD      - Recursion Desired - this bit may be set in a query and
	//                      is copied into the response. If RD is set, it
	//                      directs the name server to pursue the query 
	//                      recursively. Recursive query support is optional.
	//   RA      - Recursion Availavle - this bit is set or cleared in a 
	//                      response and denotes whether recursive query
	//                      support is available by the name server.
	//   Z       - reserved bit
	//   Answer authenticated   - 1 bit --> CURRENTLY UNSUPPORTED
	//   Non-authenticated data - 1 bit --> CURRENTLY UNSUPPORTED
	//   RCODE   - Response code - this 4 bit field is set as part of
	//                      responses.
	Flags uint16

	// QuestionCount contains the number of entries in the question section.
	QuestionCount uint16

	// AnswerCount contains the number of records in the answer section.
	AnswerCount uint16

	// AuthorityCount contains the number of authority records in this section.
	AuthorityCount uint16

	// AdditionalCount specifies the number of entries in the additional
	// records section
	AdditionalCount uint16
}

func (hdr *Header) SetQuery(isQuery bool) {
	// Inverse logic because Query=0.
	setUint16BitField(&hdr.Flags, flagQueryResponse, !isQuery)
}

// IsQuery returns true if the message is a query.
func (hdr *Header) IsQuery() bool {
	return hdr.Flags&flagQueryResponse == 0
}

func (hdr *Header) SetResponse(isResponse bool) {
	setUint16BitField(&hdr.Flags, flagQueryResponse, isResponse)
}

// IsResponse returns true if the message is a response.
func (hdr *Header) IsResponse() bool {
	return !hdr.IsQuery()
}

func (hdr *Header) SetOpcode(opcode uint16) error {
	if opcode > 0xF {
		return ErrValueTooLarge
	}

	opcode &= 0xF
	hdr.Flags |= opcode << flagOperationCodePosition
	return nil
}

// Opcode returns the kind of the message (opcode).
func (hdr *Header) Opcode() uint16 {
	return (hdr.Flags << 1) >> flagOperationCodePosition
}

func (hdr *Header) SetAuthoritativeAnswer(isAuthoritative bool) {
	setUint16BitField(&hdr.Flags, flagAuthoritativeAnswer, isAuthoritative)
}

// IsAuthoritativeAnswer is valid in responses and specifies that the
// responding name server is an authority for the domain name in the
// corresponding query.
func (hdr *Header) IsAuthoritativeAnswer() bool {
	return hdr.Flags&flagAuthoritativeAnswer != 0
}

func (hdr *Header) SetTruncated(isTruncated bool) {
	setUint16BitField(&hdr.Flags, flagTruncation, isTruncated)
}

// IsTruncated specifies that this message was truncated due to a length
// greater than 512 characters (UDP). This bit is valid only in datagram
// messages but not in messages sent over virtual circuits (TCP).
func (hdr *Header) IsTruncated() bool {
	return hdr.Flags&flagTruncation != 0
}

func (hdr *Header) SetRecursionDesired(isRecursionDesired bool) {
	setUint16BitField(&hdr.Flags, flagRecursionDesired, isRecursionDesired)
}

// IsRecursionDesired is set in a query and is copied into the response.
// If the field is set, it directs the name server to pursue the query
// recursively. Recursive query support is optional.
func (hdr *Header) IsRecursionDesired() bool {
	return hdr.Flags&flagRecursionDesired != 0
}

func (hdr *Header) SetRecursionAvailable(isRecursionAvailable bool) {
	setUint16BitField(&hdr.Flags, flagRecursionAvailable, isRecursionAvailable)
}

// IsRecursionAvailable is set or cleared in a response and denotes whether
// recursive query support is available in the name server.
func (hdr *Header) IsRecursionAvailable() bool {
	return hdr.Flags&flagRecursionAvailable != 0
}

func (hdr *Header) SetResponseCode(responseCode uint16) error {
	if responseCode > 0xF {
		return ErrValueTooLarge
	}

	responseCode &= 0xF
	hdr.Flags |= responseCode
	return nil
}

// ResponseCode is set as part of responses.
func (hdr *Header) ResponseCode() uint16 {
	return (hdr.Flags & 0xF)
}

func NewHeader() (*Header, error) {
	hdr := new(Header)

	r, err := rand.Int(rand.Reader, big.NewInt(0x7FFF))
	if err != nil {
		return nil, err
	}
	hdr.Id = uint16(r.Int64())

	return hdr, nil
}

// ReadHeader reads and parses a request from b.
func ReadHeader(b []byte) (*Header, error) {
	hdr := new(Header)

	if len(b) < 12 {
		return nil, ErrInvalidFormat
	}

	hdr.Id = byteToUint16(b[0:2])
	hdr.Flags = byteToUint16(b[2:4])
	hdr.QuestionCount = byteToUint16(b[4:6])
	hdr.AnswerCount = byteToUint16(b[6:8])
	hdr.AuthorityCount = byteToUint16(b[8:10])
	hdr.AdditionalCount = byteToUint16(b[10:12])

	return hdr, nil
}
