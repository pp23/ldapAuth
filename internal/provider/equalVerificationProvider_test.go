package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEqualVerificationSuccess(t *testing.T) {
	const expectedData string = "testFileReadSuccess"
	tmpDir, tmpDirErr := os.MkdirTemp("", "testFileReadSuccess")
	if tmpDirErr != nil {
		t.Fatal(tmpDirErr)
	}
	defer os.RemoveAll(tmpDir)
	testFile := filepath.Join(tmpDir, "testFileReadSuccess.txt")
	if err := os.WriteFile(testFile, []byte(expectedData), 0666); err != nil {
		t.Fatalf("Could not write test file: %v", err)
	}
	var evp VerificationProvider = &EqualVerificationProvider{}
	jErr := json.Unmarshal([]byte(`{
		"file": {
      "path": "`+testFile+`"
      }
	  }`), &evp)
	if jErr != nil {
		t.Fatal(jErr)
	}
	if result, err := evp.Verify([]byte(expectedData)); result == false || err != nil {
		t.Fatalf("Expected result == true and err == nil, got result \"%v\" and error \"%v\"", result, err)
	}
}
