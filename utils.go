package dns

func byteToInt16(buf []byte) int16 {
	return (int16(buf[0]) << 8) | int16(buf[1])
}

func byteToUint16(buf []byte) uint16 {
	return (uint16(buf[0]) << 8) | uint16(buf[1])
}
