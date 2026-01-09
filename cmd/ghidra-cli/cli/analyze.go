package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"

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
	server := getGhidraServer()
	
	fmt.Println("=== Function Information ===")
	funcURL := fmt.Sprintf("http://%s/get_function_by_address?address=%s", server, address)
	if resp, err := http.Get(funcURL); err == nil {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))
		resp.Body.Close()
	}
	
	fmt.Println("\n=== Decompiled Code ===")
	decompURL := fmt.Sprintf("http://%s/decompile_function?address=%s", server, address)
	if resp, err := http.Get(decompURL); err == nil {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))
		resp.Body.Close()
	}
	
	fmt.Println("\n=== Assembly Code ===")
	disasmURL := fmt.Sprintf("http://%s/disassemble_function?address=%s", server, address)
	if resp, err := http.Get(disasmURL); err == nil {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))
		resp.Body.Close()
	}
	
	fmt.Println("\n=== Cross References (to) ===")
	xrefsURL := fmt.Sprintf("http://%s/xrefs_to?address=%s&limit=20", server, address)
	if resp, err := http.Get(xrefsURL); err == nil {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))
		resp.Body.Close()
	}
}