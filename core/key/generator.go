package key

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
)

func GeneratePrivateKey(size int) (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func GenerateKeyPair(path string, size int) (*rsa.PrivateKey, error) {
	privateKey, err := GeneratePrivateKey(size)
	if err != nil {
		return nil, err
	}

	err = os.MkdirAll(path, 0755)
	if err != nil {
		return nil, err
	}

	privateKeyFile, err := os.Create(fmt.Sprintf("%s/%s", path, "private.key"))
	if err != nil {
		return nil, err
	}
	defer privateKeyFile.Close()

	err = EncodePrivateKeyToDER(privateKeyFile, privateKey)
	if err != nil {
		return nil, err
	}

	publicKeyFile, err := os.Create(fmt.Sprintf("%s/%s", path, "public.pub"))
	if err != nil {
		return nil, err
	}
	defer publicKeyFile.Close()

	err = EncodePublicKeyToDER(publicKeyFile, &privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
