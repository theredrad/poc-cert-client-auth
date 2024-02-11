package cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/theredrad/certauthz/core/common"
)

var (
	// custom OID (object identifier) for the client scope in the certificate
	scopeOID = []int{1, 2, 3, 4}
)

// NewCA returns a new x509 certificate for digital signature and cert sign purposes with given parameters
func NewCA(primaryPrivateKey, primaryPublicKey any, serialNumber int64, commonName, org string, expiration time.Duration) ([]byte, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expiration),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, primaryPublicKey, primaryPrivateKey)
	if err != nil {
		return nil, err
	}
	return certBytes, nil
}

// NewCert a new x509 certificate for the client
func NewCert(caCert *x509.Certificate, clientPublicKey, caPrivateKey any, serialNumber int64, clientName, org, scopes string, expirationTime time.Duration) ([]byte, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Organization:       []string{org},
			OrganizationalUnit: []string{"Client"},
			CommonName:         clientName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(expirationTime),
		SubjectKeyId: []byte(fmt.Sprintf("%s-key-1", clientName)),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
		Id: scopeOID,
		// Critical: true, // TODO: it can not be critical because this extension verification is not supported by the default implementation
		Value: []byte(scopes),
	})

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, clientPublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	return certBytes, nil
}

// ScopesFromCertificate returns the client scopes in the certificate
func ScopesFromCertificate(cert *x509.Certificate) common.Scopes {
	scopes := make(common.Scopes)
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(scopeOID) {
			for _, s := range strings.Split(string(ext.Value), " ") {
				scopes[s] = struct{}{}
			}
			return scopes
		}
	}
	return scopes
}
