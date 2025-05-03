package provider

import "fmt"

// A proxy that selects the provider that matches the key of one of the available providers.
// Can be used in Configurations that uses the ProviderSelector to get values provided.
// For example, with this struct:
//
// type Config struct {
//   Secret *ProviderSelector `json:"secret"`
// }
//
// The json-config that uses the file-provider looks like this:
//
// {
//   "secret": {
//     "file": {
//       "path": "/path/to/secret"
//     }
//   }
// }

// The Provider-Interface functions call the funtions of the selected, thus configured, provider.
type ProviderSelector struct {
	File        *FileProvider   `json:"file,omitempty" yaml:"file,omitempty"`
	Value       *ValueProvider  `json:"value,omitempty" yaml:"value,omitempty"`
	Environment *EnvVarProvider `json:"env,omitempty" yaml:"env,omitempty"`

	// gets set when Open() called and represents the configured provider
	selectedProvider Provider
}

// Checks which provider was actually configured and uses this for further function calls.
func (ps *ProviderSelector) Open() error {
	if ps.File != nil {
		ps.selectedProvider = ps.File
	}
	if ps.Value != nil {
		ps.selectedProvider = ps.Value
	}
	if ps.Environment != nil {
		ps.selectedProvider = ps.Environment
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
