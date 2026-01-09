package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var xrefsCmd = &cobra.Command{
	Use:   "xrefs",
	Short: "Cross-reference commands",
}

var xrefsToCmd = &cobra.Command{
	Use:   "to <address>",
	Short: "Get references to address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		limit, _ := cmd.Flags().GetInt("limit")
		getXrefsTo(address, limit)
	},
}

var xrefsFromCmd = &cobra.Command{
	Use:   "from <address>",
	Short: "Get references from address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		limit, _ := cmd.Flags().GetInt("limit")
		getXrefsFrom(address, limit)
	},
}

func init() {
	xrefsToCmd.Flags().IntP("limit", "l", 100, "Maximum number of results")
	xrefsFromCmd.Flags().IntP("limit", "l", 100, "Maximum number of results")
	
	xrefsCmd.AddCommand(xrefsToCmd)
	xrefsCmd.AddCommand(xrefsFromCmd)
	rootCmd.AddCommand(xrefsCmd)
}

func getXrefsTo(address string, limit int) {
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/xrefs_to?address=%s&limit=%d", server, address, limit)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func getXrefsFrom(address string, limit int) {
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/xrefs_from?address=%s&limit=%d", server, address, limit)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}