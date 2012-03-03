package dns

// Header implements the DNS Header field and is always present in a Message.
// The header includes fields that specify which of the remaining sections
// are present, and also specify whether the message is a query, inverse 
// query, completion query or response.
type Header struct {

}

