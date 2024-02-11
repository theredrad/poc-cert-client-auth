package cmd

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/theredrad/certauthz/core/cert"
	"github.com/theredrad/certauthz/core/file"
	"github.com/theredrad/certauthz/core/key"
)

// newCACommand returns an instance combra.Command to create a new CA certificate
func newCACommand() *cobra.Command {
	var (
		name         string
		commonName   string
		org          string
		path         string
		keySize      int
		expiration   time.Duration
		serialNumber int64
	)

	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Create a new CA certificate.",
		Long:  `Create a new CA certificate. Key pairs will be stored in the credentials directory`,
		Run: func(cmd *cobra.Command, args []string) {
			// generate primary private key
			primaryPrivateKey, err := key.GenerateKeyPair(fmt.Sprintf("%s/%s", path, name), keySize)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// generate a new CA certificate in DER format
			bytes, err := cert.NewCA(primaryPrivateKey, &primaryPrivateKey.PublicKey, serialNumber, commonName, org, expiration)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// create a new directory if not exists
			err = os.MkdirAll(fmt.Sprintf("%s/%s", path, name), 0755)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			// write the certificate to the file
			err = file.Write(fmt.Sprintf("%s/%s/ca_certificate.crt", path, name), bytes)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	// generate a serial number based on today's date. it is used as default if no serial number is passed
	serial, _ := strconv.ParseInt(time.Now().Format("20060102"), 10, 64)

	cmd.Flags().StringVarP(&path, "path", "p", "../credentials", "credentials path")
	cmd.Flags().StringVarP(&name, "name", "n", "primary", "CA identifier")
	cmd.Flags().StringVarP(&commonName, "common-name", "c", "Primary CA", "CA common name")
	cmd.Flags().StringVarP(&org, "organization", "o", "RedRad", "CA organization")
	cmd.Flags().IntVarP(&keySize, "key-size", "k", 2048, "key size")
	cmd.Flags().DurationVarP(&expiration, "expiration", "e", 8760*time.Hour, "certification expiration")
	cmd.Flags().Int64VarP(&serialNumber, "serial-number", "s", serial, "certification serial number")

	return cmd
}
