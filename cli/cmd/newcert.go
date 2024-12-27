package cmd

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/theredrad/certauthz/core/cert"
	"github.com/theredrad/certauthz/core/file"
	"github.com/theredrad/certauthz/core/key"
)

// newCertificateCmd returns a new instance of cobra.Command to generate a new client certificate
func newCertificateCmd() *cobra.Command {
	var (
		serialNumber int64
		org          string
		path         string
		caName       string
		clientName   string
		dnsNames     *[]string
		expiration   time.Duration
		scopes       string
	)

	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Create a new client certificate.",
		Long:  `Create a new client certificate. It will be stored in the client directory`,
		Run: func(cmd *cobra.Command, args []string) {
			// read CA certificate
			caCert, err := cert.ReadFromDERFile(fmt.Sprintf("%s/%s/ca_certificate.crt", path, caName))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// read primary private key
			primaryPrivateKey, err := key.ReadRSAPrivateKeyFromDERFile(fmt.Sprintf("%s/%s/private.key", path, caName))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// read client public key
			clientPublicKey, err := key.ReadRSAPublicKeyFromDERFile(fmt.Sprintf("%s/%s/public.pub", path, clientName))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// generate a new certificate in DER format. the scopes are stored as a custom extension in the certificate
			clientCert, err := cert.NewCert(caCert, clientPublicKey, primaryPrivateKey, serialNumber, clientName, org, scopes, *dnsNames, expiration)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// write the client certificate to file
			err = file.Write(fmt.Sprintf("%s/%s/certificate.crt", path, clientName), clientCert)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	// generate a serial number based on today's date plus a random number. it is used as default if no serial number is passed
	serial, _ := strconv.ParseInt(time.Now().Format("20060102"), 10, 64)
	serial = (serial * 100) + int64(rand.Intn(99)+100)

	cmd.Flags().Int64VarP(&serialNumber, "serial-number", "n", serial, "credentials path")
	cmd.Flags().StringVarP(&org, "org", "o", "RedRad", "certificate organization")
	cmd.Flags().StringVarP(&path, "path", "p", "../credentials", "credentials path")
	cmd.Flags().StringVarP(&caName, "ca-name", "a", "primary", "CA identifier")
	cmd.Flags().StringVarP(&clientName, "client-name", "c", "alice", "client name")
	cmd.Flags().DurationVarP(&expiration, "expiration", "e", 8760*time.Hour, "certification expiration")
	cmd.Flags().StringVarP(&scopes, "scopes", "s", "bob.user.read bob.user.write", "client scopes, separated by space")
	dnsNames = cmd.Flags().StringArrayP("dns", "d", []string{"localhost"}, "Certificate DNS names")

	return cmd
}
