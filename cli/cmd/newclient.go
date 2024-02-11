package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/theredrad/certauthz/core/key"
)

// newClientCmd returns a new instance of cobra.Command to generate a new client
func newClientCmd() *cobra.Command {
	var (
		name    string
		path    string
		keySize int
	)

	cmd := &cobra.Command{
		Use:   "client",
		Short: "Create a new client.",
		Long:  `Create a new client. The key pairs will be stored in the clients directory`,
		Run: func(cmd *cobra.Command, args []string) {
			_, err := key.GenerateKeyPair(fmt.Sprintf("%s/%s", path, name), keySize)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", "../credentials", "credentials path")
	cmd.Flags().StringVarP(&name, "name", "n", "alice", "Client name")
	cmd.Flags().IntVarP(&keySize, "key-size", "k", 2048, "key size")

	return cmd
}
