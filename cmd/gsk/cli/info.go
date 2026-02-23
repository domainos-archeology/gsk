package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show program metadata",
	Long: `Display metadata about the currently loaded program in Ghidra.

Shows name, format, language, compiler spec, image base, executable path,
MD5 hash, address range, and function count.

Examples:
  gsk info
`,
	Run: func(cmd *cobra.Command, args []string) {
		client := newClient()
		body, err := client.GetProgramInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(body))
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
