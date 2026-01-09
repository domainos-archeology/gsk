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
	server := getGhidraServer()
	apiURL := fmt.Sprintf("http://%s/set_local_variable_type", server)
	
	data := url.Values{}
	data.Set("function_address", functionAddr)
	data.Set("variable_name", varName)
	data.Set("new_type", newType)
	
	resp, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}