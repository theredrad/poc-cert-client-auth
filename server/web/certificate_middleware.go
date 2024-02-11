package web

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/theredrad/certauthz/core/cert"
	"github.com/theredrad/certauthz/core/common"
	"github.com/theredrad/certauthz/core/hmac"
)

const (
	// clientCertHeader base64-encoded client certificate header key
	clientCertHeader = "X-Client-Cert"

	// allowedTimeWindowSec hmac signature expiration time in second since X-Timestamp header
	allowedTimeWindowSec = 600
)

// CertificateMiddleware is a middleware to validate the client ceritificate by the CA certificate
type CertificateMiddleware struct {
	certValidator *cert.Validator
}

// NewCertificateMiddleware accepts CA certificate path and returns a new instance of CertificateMiddleware
func NewCertificateMiddleware(caPath string) (*CertificateMiddleware, error) {
	caCert, err := cert.ReadFromDERFile(caPath)
	if err != nil {
		return nil, err
	}

	return &CertificateMiddleware{
		certValidator: cert.NewValidator(caCert),
	}, nil
}

// Handle implements Middleware signature to validate the request client certificate
func (m *CertificateMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// read client base64-encoded certificate
		clientCertStr := r.Header.Get(clientCertHeader)

		// validates the client certificate by CA certificate
		clientCert, err := m.validateClientCertificate(clientCertStr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		// read hmac signature from the header
		signature := r.Header.Get("X-Signature")

		timestampStr := r.Header.Get("X-Timestamp")

		if timestampStr == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("timestamp header is missing"))
			return
		}

		requestTimestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		// validates if signature is not expired by allowed time window config
		timestampNow := time.Now().Unix()
		different := timestampNow - requestTimestamp
		if different < -allowedTimeWindowSec || different > allowedTimeWindowSec {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("timestamp is expired"))
			return
		}

		// TODO: check nonce duplication

		// calculate md5 hash of body content
		var bodyHash string
		if r.Body != nil && r.Body != http.NoBody {
			bodyHash, err = hmac.CalculateMD5Hash(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}
		}

		// validates the request hmac signature by client public key (from client certificate)
		// a valid hmac signature proves client is who it is
		err = hmac.ValidateSignature(clientCert, signature, hmac.Params{
			Method:    r.Method,
			BodyMD5:   bodyHash,
			URI:       fmt.Sprintf("%s://%s%s", "http", r.Host, r.RequestURI), // TODO: support tls
			Nonce:     r.Header.Get("X-Nonce"),
			Timestamp: timestampStr,
		})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		// read scopes from the client cerificate
		scopes := cert.ScopesFromCertificate(clientCert)

		// set the client in the context, so the handler has access to the authorized client
		ctx := setClient(r.Context(), common.Client{
			Name:   clientCert.Subject.CommonName,
			Scopes: scopes,
		})

		r = r.WithContext(ctx)
		next(w, r)
	}
}

// validateClientCertificate accepts base64-encoded client certificate and validates it
func (m *CertificateMiddleware) validateClientCertificate(clientCertStr string) (*x509.Certificate, error) {
	certBytes, err := base64.StdEncoding.DecodeString(clientCertStr)
	if err != nil {
		return nil, err
	}

	clientCert, err := cert.DecodeFromDERBytes(certBytes)
	if err != nil {
		return nil, err
	}

	err = m.certValidator.Validate(clientCert)
	if err != nil {
		return nil, err
	}

	return clientCert, nil
}
