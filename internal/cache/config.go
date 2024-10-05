package cache

type Config struct {
	Host string `json:"host,omitempty" yaml:"host,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Host: "localhost:11211",
	}
}
