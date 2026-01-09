package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var commentCmd = &cobra.Command{
	Use:   "comment",
	Short: "Add or modify comments",
}

var setDecompilerCommentCmd = &cobra.Command{
	Use:   "decompiler <address> <comment>",
	Short: "Set a decompiler (PRE) comment at address",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		comment := strings.Join(args[1:], " ")
		setDecompilerComment(address, comment)
	},
}

var setDisassemblyCommentCmd = &cobra.Command{
	Use:   "disassembly <address> <comment>",
	Short: "Set a disassembly (EOL) comment at address",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		comment := strings.Join(args[1:], " ")
		setDisassemblyComment(address, comment)
	},
}

func init() {
	commentCmd.AddCommand(setDecompilerCommentCmd)
	commentCmd.AddCommand(setDisassemblyCommentCmd)
	rootCmd.AddCommand(commentCmd)
}

func setDecompilerComment(address, comment string) {
	client := newClient()
	body, err := client.SetDecompilerComment(address, comment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func setDisassemblyComment(address, comment string) {
	client := newClient()
	body, err := client.SetDisassemblyComment(address, comment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
