package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var searchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search for functions by name",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		query := args[0]
		limit, _ := cmd.Flags().GetInt("limit")
		searchFunctions(query, limit)
	},
}

func init() {
	searchCmd.Flags().IntP("limit", "l", 100, "Maximum number of results")
	rootCmd.AddCommand(searchCmd)
}

func searchFunctions(query string, limit int) {
	server := getGhidraServer()
	apiURL := fmt.Sprintf("http://%s/searchFunctions?query=%s&limit=%d", 
		server, url.QueryEscape(query), limit)
	
	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}