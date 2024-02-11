package hmac

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

type Params struct {
	Method    string
	BodyMD5   string
	URI       string
	Nonce     string
	Timestamp string
}

func (p Params) String() string {
	return p.Method + "\n" +
		p.URI + "\n" +
		p.BodyMD5 + "\n" +
		p.Timestamp + "\n" +
		p.Nonce
}

// ValidateSignature validates the signature using ceritifcate public key
func ValidateSignature(cert *x509.Certificate, signature string, params Params) error {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %s", err)
	}
	signatureHash := sha256.Sum256([]byte(params.String()))

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to get RSA public key from certificate")
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, signatureHash[:], signatureBytes); err != nil {
		return fmt.Errorf("error while verifying the signature: %s", err)
	}

	return nil
}

func Sign(privateKey *rsa.PrivateKey, params Params) (string, error) {
	strToSignHash := sha256.Sum256([]byte(params.String()))
	sinatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, strToSignHash[:])
	if err != nil {
		return "", fmt.Errorf("error while signing: %s", err)

	}
	return base64.StdEncoding.EncodeToString(sinatureBytes), nil
}
