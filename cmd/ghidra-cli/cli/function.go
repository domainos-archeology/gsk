package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/get_function_by_address?address=%s", server, address)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func getCurrentFunction() {
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/get_current_function", server)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func listFunctions() {
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/list_functions", server)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}