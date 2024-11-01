package provider

import "fmt"

// A proxy of the available providers.
// The Provider-Interface functions call the funtions of the selected, thus configured, provider.
type ProviderSelector struct {
	File *FileProvider `json:"file,omitempty" yaml:"file,omitempty"`

	// gets set when Open() called and represents the configured provider
	selectedProvider Provider
}

// Checks which provider was actually configured and uses this for further function calls.
func (ps *ProviderSelector) Open() error {
	if ps.File != nil {
		ps.selectedProvider = ps.File
	}
	if ps.selectedProvider == nil {
		return fmt.Errorf("No known provider found in configuration")
	}
	return ps.selectedProvider.Open()
}

func (ps *ProviderSelector) Read() ([]byte, error) {
	if ps.selectedProvider == nil {
		return nil, fmt.Errorf("No provider selected. Call Open() to set the provider from the configuration.")
	}
	return ps.selectedProvider.Read()
}

func (ps *ProviderSelector) Close() error {
	if ps.selectedProvider == nil {
		return fmt.Errorf("No provider selected. Call Open() to set the provider from the configuration.")
	}
	return ps.selectedProvider.Close()
}
