package key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
)

func EncodePublicKeyToPEM(w io.Writer, pk *rsa.PublicKey) error {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkBytes,
	}

	return pem.Encode(w, pemBlock)
}

func EncodePrivateKeyToPEM(w io.Writer, pk *rsa.PrivateKey) error {
	pkBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	}
	return pem.Encode(w, pkBlock)
}

func EncodePublicKeyToDER(w io.Writer, pk *rsa.PublicKey) error {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}

	_, err = w.Write(pkBytes)
	if err != nil {
		return err
	}

	return nil
}

func EncodePrivateKeyToDER(w io.Writer, pk *rsa.PrivateKey) error {
	pkBytes, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return err
	}
	_, err = w.Write(pkBytes)
	if err != nil {
		return err
	}

	return nil
}

func DecodePrivateKeyFromDER(pkBytes []byte) (*rsa.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(pkBytes)
	if err != nil {
		return nil, err
	}

	rsaPK, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid RSA private key")
	}

	return rsaPK, nil
}

func DecodePublicKeyFromDER(pkBytes []byte) (*rsa.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return nil, err
	}

	rsaPK, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid RSA public key")
	}

	return rsaPK, nil
}

func ReadRSAPrivateKeyFromDERFile(path string) (*rsa.PrivateKey, error) {
	pkBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pk, err := DecodePrivateKeyFromDER(pkBytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func ReadRSAPublicKeyFromDERFile(path string) (*rsa.PublicKey, error) {
	pkBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pk, err := DecodePublicKeyFromDER(pkBytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}
