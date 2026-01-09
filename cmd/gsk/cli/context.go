package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var contextCmd = &cobra.Command{
	Use:   "context",
	Short: "Get current context (address + function)",
	Run: func(cmd *cobra.Command, args []string) {
		getContext()
	},
}

func init() {
	rootCmd.AddCommand(contextCmd)
}

func getContext() {
	client := newClient()

	addrBody, err := client.GetCurrentAddress()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting address: %v\n", err)
		os.Exit(1)
	}

	funcBody, err := client.GetCurrentFunction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting function: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Current Address:")
	fmt.Println(string(addrBody))
	fmt.Println("\nCurrent Function:")
	fmt.Println(string(funcBody))
}
