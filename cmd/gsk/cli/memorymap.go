package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var memorymapCmd = &cobra.Command{
	Use:   "memorymap",
	Short: "List memory blocks",
	Long: `Display the memory map of the currently loaded program.

Each line shows: name, start address, end address, size, permissions (rwx),
block type, and whether the block is initialized.

Examples:
  # List all memory blocks
  gsk memorymap

  # Limit results
  gsk memorymap --limit 50
`,
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		client := newClient()
		body, err := client.ListMemoryBlocks(limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(body))
	},
}

func init() {
	memorymapCmd.Flags().IntP("limit", "l", 1000, "Maximum number of results")
	rootCmd.AddCommand(memorymapCmd)
}
