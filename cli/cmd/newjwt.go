package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/cobra"

	"github.com/theredrad/certauthz/core/file"
	"github.com/theredrad/certauthz/core/key"
)

// newJWTTokenCmd returns a new instance of cobra.Command to generate a JWT token
func newJWTTokenCmd() *cobra.Command {
	var (
		path        string
		clientName  string
		audience    string
		scopes      string
		primaryName string
		expiration  time.Duration
	)

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Generate a new token.",
		Long:  `Generate a new token. It will be stored in the client directory`,
		Run: func(cmd *cobra.Command, args []string) {
			// read the primary private key
			primaryPrivateKey, err := key.ReadRSAPrivateKeyFromDERFile(fmt.Sprintf("%s/%s/private.key", path, primaryName))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			claims := jwt.MapClaims{
				"sub":    fmt.Sprintf("%s.local", clientName),
				"aud":    fmt.Sprintf("http://%s.local", audience),
				"iat":    time.Now().Unix(),
				"exp":    time.Now().Add(expiration).Unix(),
				"scopes": strings.Split(scopes, " "),
			}

			// a new jwt token with the claims
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

			// sign the token
			tokenStr, err := token.SignedString(primaryPrivateKey)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			err = file.Write(fmt.Sprintf("%s/%s/token", path, clientName), []byte(tokenStr))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", "../credentials", "credentials path")
	cmd.Flags().StringVarP(&primaryName, "primary-name", "a", "primary", "primary identifier including private keys")
	cmd.Flags().StringVarP(&clientName, "client-name", "c", "alice", "client identifier")
	cmd.Flags().StringVarP(&scopes, "scopes", "s", "bob.user.read bob.user.write", "scopes space-separated")
	cmd.Flags().StringVarP(&audience, "audience", "d", "bob", "audience client identifier")
	cmd.Flags().DurationVarP(&expiration, "expiration", "e", time.Hour*864000, "token expiration")

	return cmd
}
