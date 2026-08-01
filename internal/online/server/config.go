package server

import (
	"fmt"
	"time"
)

const (
	MaxTCPConnectionsLimit          = 1024
	MaxTCPConnectionsPerSourceLimit = 256
	MaxUDPDatagramBytes             = 65507
)

type Config struct {
	MaxTCPConnections          int
	MaxTCPConnectionsPerSource int
	ShutdownTimeout            time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxTCPConnections:          64,
		MaxTCPConnectionsPerSource: 8,
		ShutdownTimeout:            10 * time.Second,
	}
}

func normalizeConfig(config Config) (Config, error) {
	defaults := DefaultConfig()
	if config.MaxTCPConnections == 0 {
		config.MaxTCPConnections = defaults.MaxTCPConnections
	}
	if config.MaxTCPConnectionsPerSource == 0 {
		config.MaxTCPConnectionsPerSource = defaults.MaxTCPConnectionsPerSource
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = defaults.ShutdownTimeout
	}
	if config.MaxTCPConnections < 1 || config.MaxTCPConnections > MaxTCPConnectionsLimit {
		return Config{}, fmt.Errorf("maximum TCP connections must be between 1 and %d", MaxTCPConnectionsLimit)
	}
	if config.MaxTCPConnectionsPerSource < 1 || config.MaxTCPConnectionsPerSource > MaxTCPConnectionsPerSourceLimit {
		return Config{}, fmt.Errorf("maximum TCP connections per source must be between 1 and %d", MaxTCPConnectionsPerSourceLimit)
	}
	if config.MaxTCPConnectionsPerSource > config.MaxTCPConnections {
		return Config{}, fmt.Errorf("maximum TCP connections per source must not exceed the global maximum")
	}
	if config.ShutdownTimeout < time.Second || config.ShutdownTimeout > time.Minute {
		return Config{}, fmt.Errorf("shutdown timeout must be between 1s and 1m")
	}
	return config, nil
}
