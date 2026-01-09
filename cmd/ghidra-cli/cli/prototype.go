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

var prototypeCmd = &cobra.Command{
	Use:   "prototype <address> <prototype>",
	Short: "Set function prototype",
	Long:  "Set the function signature/prototype at the given address",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		prototype := strings.Join(args[1:], " ")
		setPrototype(address, prototype)
	},
}

func init() {
	rootCmd.AddCommand(prototypeCmd)
}

func setPrototype(address, prototype string) {
	server := getGhidraServer()
	apiURL := fmt.Sprintf("http://%s/set_function_prototype", server)
	
	data := url.Values{}
	data.Set("function_address", address)
	data.Set("prototype", prototype)
	
	resp, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}