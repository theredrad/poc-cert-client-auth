package cert

import (
	"crypto/x509"
	"io/ioutil"
)

// DecodeFromDERBytes decodes the certificate bytes in DER format to x509.Certificate
func DecodeFromDERBytes(certBytes []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// ReadFromDERFile reads the file in DER format and returns x509.Certificate
func ReadFromDERFile(path string) (*x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cert, err := DecodeFromDERBytes(certBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
