package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var renameCmd = &cobra.Command{
	Use:   "rename <address> <new_name>",
	Short: "Rename function at address",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		newName := args[1]
		renameFunction(address, newName)
	},
}

func init() {
	rootCmd.AddCommand(renameCmd)
}

func renameFunction(address, newName string) {
	server := getGhidraServer()
	apiURL := fmt.Sprintf("http://%s/rename_function_by_address", server)
	
	data := url.Values{}
	data.Set("function_address", address)
	data.Set("new_name", newName)
	
	resp, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}