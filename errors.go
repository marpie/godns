package dns

import (
	"errors"
)

var (
	ErrInvalidFormat  = errors.New("Invalid Format.")
	ErrNotImplemented = errors.New("Not Implemented.")
	ErrValueTooLarge  = errors.New("Value too large.")
)
