package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetTimestampFilePath(t *testing.T) {
	path := getTimestampFilePath()
	expected := filepath.Join(".beads", ".last_check_timestamp")
	if path != expected {
		t.Errorf("getTimestampFilePath() = %s, want %s", path, expected)
	}
}

func TestGetLastCheckTimestamp_NoFile(t *testing.T) {
	// Save current directory and change to temp dir
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Should return 0 when file doesn't exist
	timestamp := getLastCheckTimestamp()
	if timestamp != 0 {
		t.Errorf("getLastCheckTimestamp() = %d, want 0 for non-existent file", timestamp)
	}
}

func TestGetLastCheckTimestamp_ValidFile(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Create the timestamp file
	beadsDir := filepath.Join(tmpDir, ".beads")
	os.MkdirAll(beadsDir, 0755)
	timestampFile := filepath.Join(beadsDir, ".last_check_timestamp")
	os.WriteFile(timestampFile, []byte("1704723456000"), 0644)

	timestamp := getLastCheckTimestamp()
	if timestamp != 1704723456000 {
		t.Errorf("getLastCheckTimestamp() = %d, want 1704723456000", timestamp)
	}
}

func TestGetLastCheckTimestamp_InvalidContent(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Create file with invalid content
	beadsDir := filepath.Join(tmpDir, ".beads")
	os.MkdirAll(beadsDir, 0755)
	timestampFile := filepath.Join(beadsDir, ".last_check_timestamp")
	os.WriteFile(timestampFile, []byte("not-a-number"), 0644)

	// Should return 0 for invalid content
	timestamp := getLastCheckTimestamp()
	if timestamp != 0 {
		t.Errorf("getLastCheckTimestamp() = %d, want 0 for invalid content", timestamp)
	}
}

func TestGetLastCheckTimestamp_WhitespaceHandling(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Create file with whitespace around number
	beadsDir := filepath.Join(tmpDir, ".beads")
	os.MkdirAll(beadsDir, 0755)
	timestampFile := filepath.Join(beadsDir, ".last_check_timestamp")
	os.WriteFile(timestampFile, []byte("  1704723456000\n"), 0644)

	timestamp := getLastCheckTimestamp()
	if timestamp != 1704723456000 {
		t.Errorf("getLastCheckTimestamp() = %d, want 1704723456000", timestamp)
	}
}

func TestSaveLastCheckTimestamp(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Save a timestamp
	saveLastCheckTimestamp(1704723456000)

	// Verify it was saved correctly
	timestampFile := filepath.Join(".beads", ".last_check_timestamp")
	data, err := os.ReadFile(timestampFile)
	if err != nil {
		t.Fatalf("Failed to read timestamp file: %v", err)
	}

	if string(data) != "1704723456000" {
		t.Errorf("Saved timestamp = %s, want 1704723456000", string(data))
	}
}

func TestSaveLastCheckTimestamp_CreatesDirectory(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// .beads directory doesn't exist yet
	beadsDir := filepath.Join(tmpDir, ".beads")
	if _, err := os.Stat(beadsDir); !os.IsNotExist(err) {
		t.Fatal(".beads directory should not exist initially")
	}

	// Save should create the directory
	saveLastCheckTimestamp(1704723456000)

	// Verify directory was created
	if _, err := os.Stat(beadsDir); os.IsNotExist(err) {
		t.Error("saveLastCheckTimestamp() should create .beads directory")
	}
}

func TestSaveAndGetTimestamp_RoundTrip(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	testCases := []int64{
		0,
		1,
		1704723456000,
		9223372036854775807, // max int64
	}

	for _, tc := range testCases {
		saveLastCheckTimestamp(tc)
		got := getLastCheckTimestamp()
		if got != tc {
			t.Errorf("Round trip failed: saved %d, got %d", tc, got)
		}
	}
}
