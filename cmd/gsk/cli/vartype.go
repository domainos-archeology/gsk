package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var vartypeCmd = &cobra.Command{
	Use:   "vartype <function_address> <variable_name> <new_type>",
	Short: "Set local variable type",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		functionAddr := args[0]
		varName := args[1]
		newType := args[2]
		setVarType(functionAddr, varName, newType)
	},
}

func init() {
	rootCmd.AddCommand(vartypeCmd)
}

func setVarType(functionAddr, varName, newType string) {
	client := newClient()
	body, err := client.SetLocalVariableType(functionAddr, varName, newType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
