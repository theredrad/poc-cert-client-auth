package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute() {
	rootCmd := &cobra.Command{
		Use: "cli",
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new CA, Certificate, and Client",
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new JWT token",
	}

	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(generateCmd)
	createCmd.AddCommand(newClientCmd(), newCACommand(), newCertificateCmd())
	generateCmd.AddCommand(newJWTTokenCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
