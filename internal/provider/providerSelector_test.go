package provider

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

func TestProviderSelectorFileProviderSuccess(t *testing.T) {
	f, fErr := ioutil.TempFile("", "TestProviderSelectorFileProviderSuccess.txt")
	if fErr != nil {
		t.Fatal(fErr)
	}
	defer os.Remove(f.Name())
	var expectedPath string = f.Name()
	var ps ProviderSelector
	if err := json.Unmarshal([]byte(`{
      "file": {
        "path": "`+expectedPath+`"
      }
    }`), &ps); err != nil {
		t.Fatal(err)
	}
	if ps.File == nil {
		t.Fatalf("FileProvider not set in ProviderSelector")
	}
	if ps.File.Path != expectedPath {
		t.Fatalf("Expected path \"%s\", got path \"%s\"", expectedPath, ps.File.Path)
	}
	if err := ps.Open(); err != nil {
		t.Fatal(err)
	}
}
