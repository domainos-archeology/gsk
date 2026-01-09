package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/decompile_function?address=%s", server, address)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println(string(body))
}