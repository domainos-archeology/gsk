package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var disassembleCmd = &cobra.Command{
	Use:   "disassemble <address>",
	Short: "Disassemble function at address",
	Long:  "Get the assembly code for the function at the given address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		disassembleFunction(address)
	},
}

func init() {
	rootCmd.AddCommand(disassembleCmd)
}

func disassembleFunction(address string) {
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/disassemble_function?address=%s", server, address)
	
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