package config

import (
	"fmt"
	"os"
)

type Config struct {
	AWSRegion     string
	PrimaryRegion string

	CredentialsTable string
	BitIndicesTable  string
}

func Load() (*Config, error) {
	cfg := &Config{
		AWSRegion:     getEnvWithDefault("AWS_REGION", "us-east-1"),
		PrimaryRegion: getEnvWithDefault("PRIMARY_REGION", "us-east-1"),

		CredentialsTable: os.Getenv("CREDENTIALS_TABLE_NAME"),
		BitIndicesTable:  os.Getenv("BIT_INDICES_TABLE_NAME"),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	required := map[string]string{
		"CREDENTIALS_TABLE_NAME": c.CredentialsTable,
		"BIT_INDICES_TABLE_NAME": c.BitIndicesTable,
	}
	for name, val := range required {
		if val == "" {
			return fmt.Errorf("required environment variable %s is not set", name)
		}
	}
	return nil
}

func getEnvWithDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
