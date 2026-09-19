package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var programCmd = &cobra.Command{
	Use:   "program",
	Short: "Manage which programs are open in Ghidra",
	Long: `List, open, close, and save programs in the Ghidra project.

The server runs in Ghidra's project window and can open any program in the
project without a CodeBrowser window. Programs opened this way are hidden;
pass --visible to also show one in a CodeBrowser.

Examples:
  gsk program list                       # everything open, with where it's open
  gsk program open /bin/ls               # open hidden, for use with --program
  gsk program open /bin/ls --visible     # also show it in a CodeBrowser
  gsk program save /bin/ls               # write changes back to the project
  gsk program close /bin/ls              # release the server's hold on it
`,
}

var programListCmd = &cobra.Command{
	Use:   "list",
	Short: "List open programs",
	Long: `List every program open in Ghidra, one per line:

  <project path>  <name>  <flags>

Flags: active (current in a CodeBrowser), server (opened by gsk),
tool:<name> (open in that tool window), modified (unsaved changes).`,
	Run: func(cmd *cobra.Command, args []string) {
		client := newClient()
		body, err := client.ListPrograms()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(body))
	},
}

var programOpenCmd = &cobra.Command{
	Use:   "open <project-path>",
	Short: "Open a program from the project",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		visible, _ := cmd.Flags().GetBool("visible")
		client := newClient()
		body, err := client.OpenProgram(args[0], visible)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(body))
	},
}

var programCloseCmd = &cobra.Command{
	Use:   "close <project-path>",
	Short: "Release a program the server opened",
	Long: `Release the server's hold on a program. If nothing else has it open and it
has unsaved changes, the close is refused unless --force is given (the
changes are then lost).`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")
		client := newClient()
		body, err := client.CloseProgram(args[0], force)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(body))
	},
}

var programSaveCmd = &cobra.Command{
	Use:   "save [project-path]",
	Short: "Save a program's changes to the project",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		program := ""
		if len(args) == 1 {
			program = args[0]
		}
		client := newClient()
		if program == "" {
			program = client.program
		}
		body, err := client.SaveProgram(program)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(body))
	},
}

func init() {
	programOpenCmd.Flags().Bool("visible", false, "Also show the program in a CodeBrowser window")
	programCloseCmd.Flags().Bool("force", false, "Close even if unsaved changes would be lost")
	programCmd.AddCommand(programListCmd)
	programCmd.AddCommand(programOpenCmd)
	programCmd.AddCommand(programCloseCmd)
	programCmd.AddCommand(programSaveCmd)
	rootCmd.AddCommand(programCmd)
}
