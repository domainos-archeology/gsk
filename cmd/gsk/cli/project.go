package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Browse the Ghidra project",
}

var projectListCmd = &cobra.Command{
	Use:   "list [folder]",
	Short: "List files in the project",
	Long: `List files in the open Ghidra project, one per line:

  <project path>  <content type>  open|closed

Examples:
  gsk project list                  # whole project
  gsk project list /lib             # one folder, recursively
  gsk project list --programs       # only program files
  gsk project list --no-recursive   # top level only
`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		folder := ""
		if len(args) == 1 {
			folder = args[0]
		}
		noRecursive, _ := cmd.Flags().GetBool("no-recursive")
		programsOnly, _ := cmd.Flags().GetBool("programs")
		client := newClient()
		body, err := client.ListProject(folder, !noRecursive, programsOnly)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(body))
	},
}

func init() {
	projectListCmd.Flags().Bool("no-recursive", false, "Do not descend into subfolders")
	projectListCmd.Flags().Bool("programs", false, "Only list program files")
	projectCmd.AddCommand(projectListCmd)
	rootCmd.AddCommand(projectCmd)
}
