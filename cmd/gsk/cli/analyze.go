package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <address>",
	Short: "Full analysis of function (decompile + disassemble + xrefs)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		analyzeFunction(address)
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}

func analyzeFunction(address string) {
	client := newClient()

	fmt.Println("=== Function Information ===")
	if body, err := client.GetFunctionByAddress(address); err == nil {
		fmt.Println(string(body))
	}

	fmt.Println("\n=== Decompiled Code ===")
	if body, err := client.DecompileFunction(address); err == nil {
		fmt.Println(string(body))
	}

	fmt.Println("\n=== Assembly Code ===")
	if body, err := client.DisassembleFunction(address); err == nil {
		fmt.Println(string(body))
	}

	fmt.Println("\n=== Cross References (to) ===")
	if body, err := client.XrefsTo(address, 20); err == nil {
		fmt.Println(string(body))
	}
}
