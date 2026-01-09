package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var changesCmd = &cobra.Command{
	Use:   "changes",
	Short: "Get changes since last check",
	Long:  "Retrieve changes made in Ghidra since the last check timestamp",
	Run: func(cmd *cobra.Command, args []string) {
		since, _ := cmd.Flags().GetInt64("since")
		limit, _ := cmd.Flags().GetInt("limit")
		watch, _ := cmd.Flags().GetBool("watch")

		if watch {
			watchChanges(limit)
		} else {
			getChanges(since, limit)
		}
	},
}

func init() {
	changesCmd.Flags().Int64P("since", "s", 0, "Timestamp to check changes since (0 = use saved timestamp)")
	changesCmd.Flags().IntP("limit", "l", 100, "Maximum number of changes to retrieve")
	changesCmd.Flags().BoolP("watch", "w", false, "Continuously watch for changes")
	rootCmd.AddCommand(changesCmd)
}

func getChanges(since int64, limit int) {
	if since == 0 {
		since = getLastCheckTimestamp()
	}

	client := newClient()
	body, err := client.ChangesSince(since, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	output := string(body)
	if strings.Contains(output, "No changes since") {
		fmt.Println("No changes detected")
	} else {
		fmt.Print(output)
	}

	saveLastCheckTimestamp(time.Now().UnixMilli())
}

func watchChanges(limit int) {
	fmt.Println("Watching for changes (Ctrl+C to stop)...")

	lastCheck := time.Now().UnixMilli()
	client := newClient()

	for {
		time.Sleep(2 * time.Second)

		body, err := client.ChangesSince(lastCheck, limit)
		if err != nil {
			continue
		}

		output := string(body)
		if !strings.Contains(output, "No changes since") {
			fmt.Print(output)
		}

		lastCheck = time.Now().UnixMilli()
	}
}

func getLastCheckTimestamp() int64 {
	timestampFile := getTimestampFilePath()

	data, err := os.ReadFile(timestampFile)
	if err != nil {
		return 0
	}

	timestamp, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}

	return timestamp
}

func saveLastCheckTimestamp(timestamp int64) {
	timestampFile := getTimestampFilePath()

	os.MkdirAll(filepath.Dir(timestampFile), 0755)

	data := fmt.Sprintf("%d", timestamp)
	os.WriteFile(timestampFile, []byte(data), 0644)
}

func getTimestampFilePath() string {
	return filepath.Join(".beads", ".last_check_timestamp")
}
