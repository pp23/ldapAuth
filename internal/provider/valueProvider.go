package provider

// Provides directly a value from the config

type ValueProvider struct {
	Value string `json:"string" yaml:"string"`
}

func (vp *ValueProvider) Open() error {
	return nil
}

func (vp *ValueProvider) Read() ([]byte, error) {
	return []byte(vp.Value), nil
}

func (vp *ValueProvider) Close() error {
	return nil
}
