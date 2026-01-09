package cli

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
	// If since is 0, try to read from saved timestamp
	if since == 0 {
		since = getLastCheckTimestamp()
	}
	
	server := getGhidraServer()
	url := fmt.Sprintf("http://%s/changes_since?since=%d&limit=%d", server, since, limit)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	output := string(body)
	
	if strings.Contains(output, "No changes since") {
		fmt.Println("No changes detected")
	} else {
		fmt.Print(output)
	}
	
	// Save current timestamp for next check
	saveLastCheckTimestamp(time.Now().UnixMilli())
}

func watchChanges(limit int) {
	fmt.Println("Watching for changes (Ctrl+C to stop)...")
	
	lastCheck := time.Now().UnixMilli()
	
	for {
		time.Sleep(2 * time.Second)
		
		server := getGhidraServer()
		url := fmt.Sprintf("http://%s/changes_since?since=%d&limit=%d", 
			server, lastCheck, limit)
		
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		
		output := string(body)
		if !strings.Contains(output, "No changes since") {
			fmt.Print(output)
		}
		
		lastCheck = time.Now().UnixMilli()
	}
}

func getLastCheckTimestamp() int64 {
	timestampFile := getTimestampFilePath()
	
	data, err := ioutil.ReadFile(timestampFile)
	if err != nil {
		// File doesn't exist, return 0 (get all changes)
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
	
	// Ensure directory exists
	os.MkdirAll(filepath.Dir(timestampFile), 0755)
	
	data := fmt.Sprintf("%d", timestamp)
	ioutil.WriteFile(timestampFile, []byte(data), 0644)
}

func getTimestampFilePath() string {
	return filepath.Join(".beads", ".last_check_timestamp")
}