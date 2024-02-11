package cert

import "crypto/x509"

type Validator struct {
	rootCA *x509.Certificate
	opts   x509.VerifyOptions
}

// NewValidator returns a new instance of Validator
func NewValidator(rootCA *x509.Certificate) *Validator {
	roots := x509.NewCertPool()
	roots.AddCert(rootCA)

	return &Validator{
		rootCA: rootCA,
		opts: x509.VerifyOptions{
			Roots: roots,
		},
	}
}

// Validate validates x509.Certificate by CA cerificate
func (m Validator) Validate(cert *x509.Certificate) error {
	_, err := cert.Verify(m.opts)
	return err
}
