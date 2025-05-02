package main

import (
	"fmt"
	"time"
)

// Persistent Storage
type StoragePlugin interface {
	GatewayPlugin

	// Storage methods
	Get(key string) ([]byte, error)
	Set(key string, value []byte, ttl time.Duration) error
	Delete(key string) error
	Exists(key string) (bool, error)
	List(prefix string) ([]string, error)
	Close() error

	// Configuration specific methods
	SaveConfig(config *Config) error
	LoadConfig() (*Config, error)

	// Basic Auth specific methods
	SaveBasicAuth(users map[string]string) error
	LoadBasicAuth() (map[string]string, error)
}

// Add this to your gateway.go file
type StorageManager struct {
	storage StoragePlugin
	logger  *Logger
}

func NewStorageManager(logger *Logger) *StorageManager {
	return &StorageManager{
		logger: logger,
	}
}

func (sm *StorageManager) SetStorage(plugin StoragePlugin) {
	sm.storage = plugin
}

func (sm *StorageManager) Get(key string) ([]byte, error) {
	if sm.storage == nil {
		return nil, fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.Get(key)
}

func (sm *StorageManager) Set(key string, value []byte, ttl time.Duration) error {
	if sm.storage == nil {
		return fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.Set(key, value, ttl)
}

func (sm *StorageManager) Delete(key string) error {
	if sm.storage == nil {
		return fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.Delete(key)
}

func (sm *StorageManager) Exists(key string) (bool, error) {
	if sm.storage == nil {
		return false, fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.Exists(key)
}

func (sm *StorageManager) List(prefix string) ([]string, error) {
	if sm.storage == nil {
		return nil, fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.List(prefix)
}

func (sm *StorageManager) Close() error {
	if sm.storage == nil {
		return nil
	}
	return sm.storage.Close()
}

// Add these methods to StorageManager
func (sm *StorageManager) SaveConfig(config *Config) error {
	if sm.storage == nil {
		return fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.SaveConfig(config)
}

func (sm *StorageManager) LoadConfig() (*Config, error) {
	if sm.storage == nil {
		return nil, fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.LoadConfig()
}

func (sm *StorageManager) SaveBasicAuth(users map[string]string) error {
	if sm.storage == nil {
		return fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.SaveBasicAuth(users)
}

func (sm *StorageManager) LoadBasicAuth() (map[string]string, error) {
	if sm.storage == nil {
		return nil, fmt.Errorf("no storage plugin configured")
	}
	return sm.storage.LoadBasicAuth()
}
