package cli

import (
	"fmt"
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
	client := newClient()
	body, err := client.XrefsTo(address, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func getXrefsFrom(address string, limit int) {
	client := newClient()
	body, err := client.XrefsFrom(address, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
