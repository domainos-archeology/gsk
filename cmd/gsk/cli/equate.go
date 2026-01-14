package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var equateCmd = &cobra.Command{
	Use:   "equate",
	Short: "Equate (named constant) operations",
}

var listEquatesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all equates",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		listEquates(limit)
	},
}

var getEquateCmd = &cobra.Command{
	Use:   "get",
	Short: "Get detailed information about an equate",
	Long: `Get detailed information about an equate by name or value.

Examples:
  # Get by name
  gsk equate get --name STATUS_OK

  # Get by value (decimal or hex)
  gsk equate get --value 0x1234
  gsk equate get --value 42
`,
	Run: func(cmd *cobra.Command, args []string) {
		name, _ := cmd.Flags().GetString("name")
		value, _ := cmd.Flags().GetString("value")
		if name != "" {
			getEquateByName(name)
		} else if value != "" {
			getEquateByValue(value)
		} else {
			fmt.Fprintln(os.Stderr, "Error: must specify --name or --value")
			os.Exit(1)
		}
	},
}

var setEquateCmd = &cobra.Command{
	Use:   "set <name> <value>",
	Short: "Create or update an equate",
	Long: `Create or update an equate (named constant).

Examples:
  # Create a global equate
  gsk equate set STATUS_OK 0

  # Create an equate and apply it at an address
  gsk equate set MAX_SIZE 0x100 --address 0x401234

  # Apply to a specific operand
  gsk equate set BUFFER_LEN 256 --address 0x401234 --operand 1
`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		address, _ := cmd.Flags().GetString("address")
		operand, _ := cmd.Flags().GetInt("operand")
		setEquate(args[0], args[1], address, operand)
	},
}

var deleteEquateCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an equate or remove a reference",
	Long: `Delete an equate entirely, or remove its reference at a specific address.

Examples:
  # Delete an equate completely
  gsk equate delete STATUS_OK

  # Remove equate reference at a specific address
  gsk equate delete STATUS_OK --address 0x401234

  # Remove from specific operand
  gsk equate delete STATUS_OK --address 0x401234 --operand 1
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		address, _ := cmd.Flags().GetString("address")
		operand, _ := cmd.Flags().GetInt("operand")
		deleteEquate(args[0], address, operand)
	},
}

func init() {
	listEquatesCmd.Flags().IntP("limit", "l", 1000, "Maximum number of results")

	getEquateCmd.Flags().StringP("name", "n", "", "Equate name")
	getEquateCmd.Flags().StringP("value", "v", "", "Equate value (decimal or hex with 0x prefix)")

	setEquateCmd.Flags().StringP("address", "a", "", "Address to apply equate at")
	setEquateCmd.Flags().IntP("operand", "o", 0, "Operand index at the address")

	deleteEquateCmd.Flags().StringP("address", "a", "", "Address to remove equate from (if not specified, deletes entire equate)")
	deleteEquateCmd.Flags().IntP("operand", "o", 0, "Operand index at the address")

	equateCmd.AddCommand(listEquatesCmd)
	equateCmd.AddCommand(getEquateCmd)
	equateCmd.AddCommand(setEquateCmd)
	equateCmd.AddCommand(deleteEquateCmd)
	rootCmd.AddCommand(equateCmd)
}

func listEquates(limit int) {
	client := newClient()
	body, err := client.ListEquates(limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func getEquateByName(name string) {
	client := newClient()
	body, err := client.GetEquate(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func getEquateByValue(value string) {
	client := newClient()
	body, err := client.GetEquateByValue(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func setEquate(name, value, address string, operand int) {
	client := newClient()
	body, err := client.SetEquate(name, value, address, operand)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func deleteEquate(name, address string, operand int) {
	client := newClient()
	body, err := client.DeleteEquate(name, address, operand)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
