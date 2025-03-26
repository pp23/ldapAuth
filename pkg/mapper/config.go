package mapper

type Mappings struct {
	// Map of source key -> target key
	KeyMapping map[string]string `json:"keys,omitempty" yaml:"keys,omitempty"`
	// TODO: Define script based mappings
}
