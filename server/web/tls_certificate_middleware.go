package web

import (
	"net/http"

	"github.com/theredrad/certauthz/core/cert"
	"github.com/theredrad/certauthz/core/common"
)

// TLSCertificateMiddleware is a middleware to parse validated certificate and pass the scopes in the context
type TLSCertificateMiddleware struct{}

// NewTLSCertificateMiddleware returns a new instance of TLSCertificateMiddleware
func NewTLSCertificateMiddleware() *TLSCertificateMiddleware {
	return &TLSCertificateMiddleware{}
}

// Handle implements Middleware signature to validate the request client certificate
func (m *TLSCertificateMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientCert, ok := r.TLS.PeerCertificates[0], len(r.TLS.PeerCertificates) > 0
		if !ok {
			http.Error(w, "client certificate not found", http.StatusUnauthorized)
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
