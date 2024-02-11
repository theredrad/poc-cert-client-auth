package hmac

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

func CalculateMD5Hash(reader io.Reader) (string, error) {
	hash := md5.New()

	_, err := io.Copy(hash, reader)
	if err != nil {
		return "", err
	}

	hashBytes := hash.Sum(nil)

	hashStr := hex.EncodeToString(hashBytes)
	return hashStr, nil
}
