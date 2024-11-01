package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileReadSuccess(t *testing.T) {
	const expectedData string = "testFileReadSuccess"
	tmpDir, tmpDirErr := os.MkdirTemp("", "testFileReadSuccess")
	if tmpDirErr != nil {
		t.Fatal(tmpDirErr)
	}
	defer os.RemoveAll(tmpDir)
	testFile := filepath.Join(tmpDir, "testFileReadSuccess.txt")
	if err := os.WriteFile(testFile, []byte("testFileReadSuccess"), 0666); err != nil {
		t.Fatalf("Could not write test file: %v", err)
	}
	var fp Provider = &FileProvider{}
	jErr := json.Unmarshal([]byte(`{
     "path": "`+testFile+`"
	  }`), &fp)
	if jErr != nil {
		t.Fatal(jErr)
	}
	if err := fp.Open(); err != nil {
		t.Fatalf("Could not open file: %v", err)
	}
	data, err := fp.Read()
	if err != nil {
		t.Fatalf("Could not read provided data: %v", err)
	}
	if string(data) != expectedData {
		t.Fatalf("Expected \"%s\", got \"%s\"", expectedData, string(data))
	}
}
