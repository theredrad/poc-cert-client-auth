package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/theredrad/certauthz/client/util"
	"github.com/theredrad/certauthz/core/hmac"
	"github.com/theredrad/certauthz/core/key"
	coreTLS "github.com/theredrad/certauthz/core/tls"
)

var (
	primaryName = "primary"
	clientName  = "alice"
	serverAddr  = "http://localhost:8585"
	method      = "cert"
	path        = "../credentials"
)

func init() {
	flag.StringVar(&primaryName, "primary-name", "primary", "primary name including ca certificate and public key")
	flag.StringVar(&clientName, "client-name", "alice", "client name")
	flag.StringVar(&serverAddr, "server-addr", "http://localhost:8585", "server address")
	flag.StringVar(&method, "auth-method", "cert", "authorization method. e.g. cert, token")
	flag.StringVar(&path, "path", "../credentials", "credentials path")
	flag.Parse()
}

func main() {
	client := &http.Client{}

	var (
		r   *http.Request
		err error
	)

	switch method {
	case "token":
		r, err = newTokenRequest()
	case "mtls":
		tlsConfig, err := coreTLS.NewClientConfig(
			fmt.Sprintf("%s/%s/ca_certificate.crt", path, primaryName),
			fmt.Sprintf("%s/%s/certificate.crt", path, clientName),
			fmt.Sprintf("%s/%s/private.key", path, clientName),
		)
		if err != nil {
			log.Fatal(err)
		}

		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		r, err = newTLSRequest()
	default:
		r, err = newCertRequest()
	}
	if err != nil {
		fmt.Println("Error initializing request:", err)
		return
	}

	// send the request
	resp, err := client.Do(r)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Print the response
	fmt.Printf("Response from server: %s\n", body)
}

// newTokenRequest initializes and returns http request for token auth method
func newTokenRequest() (*http.Request, error) {
	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/token", serverAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("error while initializing new reuqest: %w", err)
	}

	// read client's token file
	clientToken, err := ioutil.ReadFile(fmt.Sprintf("%s/%s/token", path, clientName))
	if err != nil {
		return nil, fmt.Errorf("error while reading client token: %w", err)
	}

	r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(clientToken))) // set the token in the header

	return r, nil
}

// newCertRequest initializes and returns http ruquest for certificate auth method
func newCertRequest() (*http.Request, error) {
	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/cert", serverAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("error while initializing new reuqest: %w", err)
	}

	// read the client private key (requester)
	clientPrivateKeyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s/%s/private.key", path, clientName))
	if err != nil {
		return nil, fmt.Errorf("error while reading client private key: %w", err)
	}

	// decode the client private key
	clientPrivateKey, err := key.DecodePrivateKeyFromDER(clientPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error while decoding client private key: %w", err)
	}

	// reads the client certificate
	clientCert, err := ioutil.ReadFile(fmt.Sprintf("%s/%s/certificate.crt", path, clientName))
	if err != nil {
		return nil, fmt.Errorf("error while reading client certificate: %w", err)
	}

	// encode the certificate with base64 and set it in the request's header
	r.Header.Add("X-Client-Cert", base64.StdEncoding.EncodeToString(clientCert))

	nonce, err := util.GenerateRandomNonce()
	if err != nil {
		return nil, fmt.Errorf("error while generating nonce: %w", err)
	}

	nonceStr := strconv.FormatUint(nonce, 10)
	r.Header.Add("X-Nonce", nonceStr) // set random nonce header

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	r.Header.Add("X-Timestamp", timestamp) // set the current timestamp

	var bodyHash string
	if r.Body != nil {
		bodyHash, err = hmac.CalculateMD5Hash(r.Body) // calculate the request md5 hash
		if err != nil {
			return nil, fmt.Errorf("error while calculating body hash: %w", err)
		}
	}

	// sign the request with client private key, thus the server can validate the request signature
	signature, err := hmac.Sign(clientPrivateKey, hmac.Params{
		Method:    r.Method,
		BodyMD5:   bodyHash,
		URI:       r.URL.String(),
		Nonce:     nonceStr,
		Timestamp: timestamp,
	})
	if err != nil {
		return nil, fmt.Errorf("error while signing the request: %w", err)
	}
	r.Header.Add("X-Signature", signature) // set the request signature

	return r, nil
}

func newTLSRequest() (*http.Request, error) {
	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/", serverAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("error while initializing new reuqest: %w", err)
	}

	return r, nil
}
