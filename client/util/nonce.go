package util

import (
	"crypto/rand"
	"encoding/binary"
)

// GenerateRandomNonce returns a random nonce
func GenerateRandomNonce() (uint64, error) {
	var randomBytes [8]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(randomBytes[:]), nil
}
