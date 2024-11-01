package provider

import (
	"fmt"
	"io/ioutil"
	"os"
)

type FileProvider struct {
	Path string `json:"path" yaml:"path"`
}

func (fp *FileProvider) Open() error {
	if fp.Path == "" {
		return fmt.Errorf("No path set")
	}
	if _, err := os.Stat(fp.Path); err != nil {
		return err
	}
	return nil
}

func (fp *FileProvider) Read() ([]byte, error) {
	return ioutil.ReadFile(fp.Path)
}

func (fp *FileProvider) Close() error {
	// nothing to do
	return nil
}
