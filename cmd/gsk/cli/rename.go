package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var renameCmd = &cobra.Command{
	Use:   "rename <address> <new_name>",
	Short: "Rename function at address",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		newName := args[1]
		renameFunction(address, newName)
	},
}

func init() {
	rootCmd.AddCommand(renameCmd)
}

func renameFunction(address, newName string) {
	client := newClient()
	body, err := client.RenameFunction(address, newName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
