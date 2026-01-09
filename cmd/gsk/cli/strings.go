package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var stringsCmd = &cobra.Command{
	Use:   "strings",
	Short: "List defined strings",
	Run: func(cmd *cobra.Command, args []string) {
		filter, _ := cmd.Flags().GetString("filter")
		limit, _ := cmd.Flags().GetInt("limit")
		listStrings(filter, limit)
	},
}

func init() {
	stringsCmd.Flags().StringP("filter", "f", "", "Filter strings by content")
	stringsCmd.Flags().IntP("limit", "l", 100, "Maximum number of results")
	rootCmd.AddCommand(stringsCmd)
}

func listStrings(filter string, limit int) {
	client := newClient()
	body, err := client.Strings(filter, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
