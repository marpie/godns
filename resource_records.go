package dns

// ResourceRecords implements the answering resource records (RRs) defined in
// the DNS RFC 883.
type ResourceRecord struct {
	// A compressed domain name to which this resource record pertains.
	Name DNSName

	// This field specifies the meaning of the data in the Data field.
	Type uint16

	// Class specifies the category of data in the Data field.
	Class uint16

	// TTL specifies the time interval (in seconds) that the resource record
	// may be cached before it should be discarded. Zero values are interpreted
	// to mean that the RR can only be used for the transaction in progress and
	// should not be cached. For example, SOA records are always distributed 
	// with a zero TTL to prohibit caching. Zero values can also be used for
	// extremely volatile data.
	TTL uint32

	// Length specifies the length of the Data field in bytes.
	Length uint16

	// The format of this informations varies according to the Type and Class
	// of the RR.
	Data []byte
}

func (rr *ResourceRecord) Encode(rawMsg []byte) (newRaw []byte) {
	// encode name
	newRaw = rr.Name.Encode(rawMsg)

	buf := make([]byte, 10)
	uint16ToByte(rr.Type, buf)
	uint16ToByte(rr.Class, buf[2:4])
	uint32ToByte(rr.TTL, buf[4:8])
	uint16ToByte(rr.Length, buf[8:10])

	newRaw = append(newRaw[:], buf...)
	newRaw = append(newRaw[:], rr.Data...)

	return
}

func ReadResourceRecord(b []byte, rawMsg []byte) (rr *ResourceRecord, err error, nextIdx int) {
	rr = new(ResourceRecord)

	rr.Name, err, nextIdx = DecodeDNSName(b, rawMsg)
	if err != nil {
		return nil, err, 0
	}
	if len(b) < nextIdx+10 {
		return nil, ErrInvalidFormat, 0
	}

	rr.Type = byteToUint16(b[nextIdx : nextIdx+2])
	rr.Class = byteToUint16(b[nextIdx+2 : nextIdx+4])
	rr.TTL = byteToUint32(b[nextIdx+4 : nextIdx+8])
	rr.Length = byteToUint16(b[nextIdx+8 : nextIdx+10])
	start := nextIdx + 10
	nextIdx = start + int(rr.Length)
	if len(b) < nextIdx {
		return nil, ErrInvalidFormat, 0
	}
	rr.Data = b[start:nextIdx]

	return
}
