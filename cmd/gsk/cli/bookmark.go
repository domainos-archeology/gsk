package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var bookmarkCmd = &cobra.Command{
	Use:   "bookmark",
	Short: "Bookmark operations (list/add/delete)",
}

var listBookmarksCmd = &cobra.Command{
	Use:   "list",
	Short: "List bookmarks",
	Long: `List all bookmarks in the program, optionally filtered by type.

Examples:
  # List all bookmarks
  gsk bookmark list

  # List only Note bookmarks
  gsk bookmark list --type Note

  # Limit results
  gsk bookmark list --limit 100
`,
	Run: func(cmd *cobra.Command, args []string) {
		bookmarkType, _ := cmd.Flags().GetString("type")
		limit, _ := cmd.Flags().GetInt("limit")
		client := newClient()
		body, err := client.ListBookmarks(bookmarkType, limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(body))
	},
}

var addBookmarkCmd = &cobra.Command{
	Use:   "add <address> <comment>",
	Short: "Add a bookmark at an address",
	Long: `Create a bookmark at the specified address.

Examples:
  # Add a Note bookmark
  gsk bookmark add 0x401000 "check this"

  # Add with specific type and category
  gsk bookmark add 0x401000 "suspicious call" --type Note --category "Review"
`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		bookmarkType, _ := cmd.Flags().GetString("type")
		category, _ := cmd.Flags().GetString("category")
		client := newClient()
		body, err := client.SetBookmark(args[0], bookmarkType, category, args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(body))
	},
}

var deleteBookmarkCmd = &cobra.Command{
	Use:   "delete <address>",
	Short: "Delete a bookmark at an address",
	Long: `Remove a bookmark from the specified address.

Examples:
  # Delete a Note bookmark at an address
  gsk bookmark delete 0x401000

  # Delete a bookmark with specific type and category
  gsk bookmark delete 0x401000 --type Note --category "Review"
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		bookmarkType, _ := cmd.Flags().GetString("type")
		category, _ := cmd.Flags().GetString("category")
		client := newClient()
		body, err := client.DeleteBookmark(args[0], bookmarkType, category)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(body))
	},
}

func init() {
	listBookmarksCmd.Flags().StringP("type", "t", "", "Filter by bookmark type (e.g., Note, Warning, Error)")
	listBookmarksCmd.Flags().IntP("limit", "l", 1000, "Maximum number of results")

	addBookmarkCmd.Flags().StringP("type", "t", "Note", "Bookmark type")
	addBookmarkCmd.Flags().StringP("category", "c", "", "Bookmark category")

	deleteBookmarkCmd.Flags().StringP("type", "t", "Note", "Bookmark type")
	deleteBookmarkCmd.Flags().StringP("category", "c", "", "Bookmark category")

	bookmarkCmd.AddCommand(listBookmarksCmd)
	bookmarkCmd.AddCommand(addBookmarkCmd)
	bookmarkCmd.AddCommand(deleteBookmarkCmd)
	rootCmd.AddCommand(bookmarkCmd)
}
