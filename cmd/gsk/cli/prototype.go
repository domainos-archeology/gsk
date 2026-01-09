package cli

import (
	"fmt"
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
	client := newClient()
	body, err := client.SetFunctionPrototype(address, prototype)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
