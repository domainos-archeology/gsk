package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
	server := getGhidraServer()
	
	// Get current address
	addrURL := fmt.Sprintf("http://%s/get_current_address", server)
	addrResp, err := http.Get(addrURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting address: %v\n", err)
		os.Exit(1)
	}
	defer addrResp.Body.Close()
	
	addrBody, _ := ioutil.ReadAll(addrResp.Body)
	
	// Get current function
	funcURL := fmt.Sprintf("http://%s/get_current_function", server)
	funcResp, err := http.Get(funcURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting function: %v\n", err)
		os.Exit(1)
	}
	defer funcResp.Body.Close()
	
	funcBody, _ := ioutil.ReadAll(funcResp.Body)
	
	fmt.Println("Current Address:")
	fmt.Println(string(addrBody))
	fmt.Println("\nCurrent Function:")
	fmt.Println(string(funcBody))
}