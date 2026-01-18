package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var dataCmd = &cobra.Command{
	Use:   "data",
	Short: "Data type operations at memory addresses",
}

var getDataCmd = &cobra.Command{
	Use:   "get <address>",
	Short: "Get data type information at an address",
	Long: `Display information about data defined at the specified address.

Shows the data type, size, value representation, and any labels.

Examples:
  # Get data info at address
  gsk data get 0x401234
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		getData(args[0])
	},
}

var setDataTypeCmd = &cobra.Command{
	Use:   "set <address> <type>",
	Short: "Assign a data type to an address",
	Long: `Assign a data type to a memory location.

This command marks the memory at the specified address as containing
data of the given type. Common built-in types are supported:

Primitive types:
  byte, word, dword, qword     - Unsigned integers (1, 2, 4, 8 bytes)
  short, int, long             - Signed integers (2, 4, 8 bytes)
  char                         - Single character
  float, double                - Floating point (4, 8 bytes)
  bool                         - Boolean
  pointer, ptr                 - Pointer (architecture-dependent size)
  string                       - Null-terminated string

Legacy/disassembler style:
  db, dw, dd, dq               - Define byte, word, dword, qword

Undefined types (when you know size but not meaning):
  undefined, undefined1        - 1 byte
  undefined2                   - 2 bytes
  undefined4                   - 4 bytes
  undefined8                   - 8 bytes

Custom types:
  Any struct, union, typedef, or enum defined in the program

Pointer syntax:
  "int *" or "int*"           - Pointer to int

Examples:
  # Mark as a 32-bit integer
  gsk data set 0x401234 dword

  # Mark as a custom struct
  gsk data set 0x401234 MyStruct

  # Mark as a null-terminated string
  gsk data set 0x401234 string

  # Mark as a pointer to int
  gsk data set 0x401234 "int *"
`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		setDataType(args[0], args[1])
	},
}

var clearDataCmd = &cobra.Command{
	Use:   "clear <address> [length]",
	Short: "Clear defined data at an address",
	Long: `Clear any data definition at the specified address.

This removes any data type assignment, converting the bytes back
to undefined. Optionally specify a length to clear multiple bytes.

Examples:
  # Clear single data item at address
  gsk data clear 0x401234

  # Clear 16 bytes starting at address
  gsk data clear 0x401234 16
  gsk data clear 0x401234 --length 16
`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		address := args[0]
		length, _ := cmd.Flags().GetInt("length")

		// If length provided as second positional arg, use that
		if len(args) >= 2 {
			var argLen int
			_, err := fmt.Sscanf(args[1], "%d", &argLen)
			if err == nil && argLen > 0 {
				length = argLen
			}
		}

		clearData(address, length)
	},
}

func init() {
	clearDataCmd.Flags().IntP("length", "l", 1, "Number of bytes to clear")

	dataCmd.AddCommand(getDataCmd)
	dataCmd.AddCommand(setDataTypeCmd)
	dataCmd.AddCommand(clearDataCmd)
	rootCmd.AddCommand(dataCmd)
}

func getData(address string) {
	client := newClient()
	body, err := client.GetData(address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func setDataType(address, typeName string) {
	client := newClient()
	body, err := client.SetDataType(address, typeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}

func clearData(address string, length int) {
	client := newClient()
	body, err := client.ClearData(address, length)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
