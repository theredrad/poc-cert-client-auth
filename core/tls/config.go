package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/theredrad/certauthz/core/cert"
	"github.com/theredrad/certauthz/core/key"
)

var (
	// custom OID (object identifier) for the client scope in the certificate
	scopeOID = []int{1, 2, 3, 4}
)

// NewServerConfig returns an instance of tls config based on server configuration to enforce mtls
// the certificate scope extension is validated if requiredScopePrefix is passed
// the client certificate must have the requiredScopePrefix in at least of of the scopes e.g. bob.read (bob.*)
func NewServerConfig(caPath, serverCertPath, serverPrivateKeyPath, requiredScopePrefix string) (*tls.Config, error) {
	caCert, err := cert.ReadFromDERFile(caPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	serverCert, err := cert.ReadFromDERFile(serverCertPath)
	if err != nil {
		return nil, err
	}

	var serverTLSCert tls.Certificate
	serverTLSCert.Certificate = append(serverTLSCert.Certificate, serverCert.Raw)

	serverPrivateKey, err := key.ReadRSAPrivateKeyFromDERFile(serverPrivateKeyPath)
	if err != nil {
		return nil, err
	}

	serverTLSCert.PrivateKey = serverPrivateKey

	var peerCertVerifierFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	if requiredScopePrefix != "" {
		peerCertVerifierFunc = NewPeerCertVerifierFuncWithScopePrefix(requiredScopePrefix)
	}

	return &tls.Config{
		Certificates:          []tls.Certificate{serverTLSCert},
		ClientCAs:             caCertPool,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: peerCertVerifierFunc,
	}, nil
}

// NewClientConfig returns an instance of tls config based on client configuration to enforce mtls
// no prefix scope is required on the client side in our case, however it might be required since it's a mutual tls
func NewClientConfig(caPath, clientCertPath, clientPrivateKeyPath string) (*tls.Config, error) {
	caCert, err := cert.ReadFromDERFile(caPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	clientCert, err := cert.ReadFromDERFile(clientCertPath)
	if err != nil {
		return nil, err
	}

	var clientTLSCert tls.Certificate
	clientTLSCert.Certificate = append(clientTLSCert.Certificate, clientCert.Raw)

	clientPrivateKey, err := key.ReadRSAPrivateKeyFromDERFile(clientPrivateKeyPath)
	if err != nil {
		return nil, err
	}

	clientTLSCert.PrivateKey = clientPrivateKey

	return &tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// NewPeerCertVerifierFuncWithScopePrefix returns peer certificate verifier function to enforce having at least one scope (as custom certificate extension) with the prefix
func NewPeerCertVerifierFuncWithScopePrefix(scopePrefix string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// only first certificate is inspected for test purposes
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(scopeOID) {
				for _, s := range strings.Split(string(ext.Value), " ") {
					if s[:len(scopePrefix)] == scopePrefix { // the certificate scopes has the required prefix
						return nil
					}
				}
			}
		}

		return errors.New("the peer is not authorized for the communication")
	}
}
