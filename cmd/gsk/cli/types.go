package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var typeCmd = &cobra.Command{
	Use:   "type",
	Short: "Data type operations",
}

var listTypesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all data types",
	Run: func(cmd *cobra.Command, args []string) {
		category, _ := cmd.Flags().GetString("category")
		limit, _ := cmd.Flags().GetInt("limit")
		listTypes(category, limit)
	},
}

var getTypeCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get detailed information about a type",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		getType(args[0])
	},
}

var searchTypesCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search types by name",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		searchTypes(args[0], limit)
	},
}

var createTypeCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new data type",
	Long: `Create a new data type. Supported kinds: struct, union, typedef, enum

Examples:
  # Create an empty struct
  gsk type create MyStruct --kind struct

  # Create a struct with fields
  gsk type create Point --kind struct --definition "int x; int y"

  # Create a typedef/alias
  gsk type create DWORD --kind typedef --definition uint

  # Create an enum
  gsk type create Status --kind enum --definition "OK=0; ERROR=1; PENDING=2"

  # Create a union
  gsk type create IntOrFloat --kind union --definition "int i; float f"
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		kind, _ := cmd.Flags().GetString("kind")
		definition, _ := cmd.Flags().GetString("definition")
		createType(args[0], kind, definition)
	},
}

var updateTypeCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update an existing data type",
	Long: `Update an existing data type. Can rename or modify definition.

Examples:
  # Rename a type
  gsk type update OldName --new-name NewName

  # Update struct fields (replaces all existing fields)
  gsk type update MyStruct --definition "int x; int y; int z"

  # Update enum values
  gsk type update Status --definition "OK=0; ERROR=1; WARNING=2; PENDING=3"
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		newName, _ := cmd.Flags().GetString("new-name")
		definition, _ := cmd.Flags().GetString("definition")
		updateType(args[0], newName, definition)
	},
}

func init() {
	listTypesCmd.Flags().StringP("category", "c", "", "Filter by category path")
	listTypesCmd.Flags().IntP("limit", "l", 1000, "Maximum number of results")

	searchTypesCmd.Flags().IntP("limit", "l", 100, "Maximum number of results")

	createTypeCmd.Flags().StringP("kind", "k", "struct", "Type kind: struct, union, typedef, enum")
	createTypeCmd.Flags().StringP("definition", "d", "", "Type definition (format depends on kind)")

	updateTypeCmd.Flags().StringP("new-name", "n", "", "New name for the type")
	updateTypeCmd.Flags().StringP("definition", "d", "", "New definition (for struct/union/enum)")

	typeCmd.AddCommand(listTypesCmd)
	typeCmd.AddCommand(getTypeCmd)
	typeCmd.AddCommand(searchTypesCmd)
	typeCmd.AddCommand(createTypeCmd)
	typeCmd.AddCommand(updateTypeCmd)
	rootCmd.AddCommand(typeCmd)
}

func listTypes(category string, limit int) {
	client := newClient()
	body, err := client.ListTypes(category, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func getType(name string) {
	client := newClient()
	body, err := client.GetType(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func searchTypes(query string, limit int) {
	client := newClient()
	body, err := client.SearchTypes(query, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func createType(name, kind, definition string) {
	client := newClient()
	body, err := client.CreateType(name, kind, definition)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func updateType(name, newName, definition string) {
	client := newClient()
	body, err := client.UpdateType(name, newName, definition)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
