package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var functionCmd = &cobra.Command{
	Use:   "function",
	Short: "Function-related commands",
}

var getFunctionCmd = &cobra.Command{
	Use:   "get <address>",
	Short: "Get function information by address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		getFunctionByAddress(address)
	},
}

var getCurrentFunctionCmd = &cobra.Command{
	Use:   "current",
	Short: "Get currently selected function in Ghidra",
	Run: func(cmd *cobra.Command, args []string) {
		getCurrentFunction()
	},
}

var listFunctionsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all functions",
	Run: func(cmd *cobra.Command, args []string) {
		listFunctions()
	},
}

func init() {
	functionCmd.AddCommand(getFunctionCmd)
	functionCmd.AddCommand(getCurrentFunctionCmd)
	functionCmd.AddCommand(listFunctionsCmd)
	rootCmd.AddCommand(functionCmd)
}

func getFunctionByAddress(address string) {
	client := newClient()
	body, err := client.GetFunctionByAddress(address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func getCurrentFunction() {
	client := newClient()
	body, err := client.GetCurrentFunction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func listFunctions() {
	client := newClient()
	body, err := client.ListFunctions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
