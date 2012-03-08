package dns

func byteToInt16(buf []byte) int16 {
	return (int16(buf[0]) << 8) | int16(buf[1])
}

func byteToUint16(buf []byte) uint16 {
	return (uint16(buf[0]) << 8) | uint16(buf[1])
}

func byteToUint32(buf []byte) uint32 {
	return (uint32(buf[0]) << 24) | (uint32(buf[1]) << 16) | (uint32(buf[2]) << 8) | uint32(buf[3])
}

func setUint16BitField(ui *uint16, bitMask uint16, setField bool) {
	if setField {
		*ui |= bitMask
	} else {
		*ui &= ^bitMask
	}
}
