package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var decompileCmd = &cobra.Command{
	Use:   "decompile <address>",
	Short: "Decompile function at address",
	Long:  "Decompile the function at the given address and display the C pseudocode",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		decompileFunction(address)
	},
}

func init() {
	rootCmd.AddCommand(decompileCmd)
}

func decompileFunction(address string) {
	client := newClient()
	body, err := client.DecompileFunction(address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
