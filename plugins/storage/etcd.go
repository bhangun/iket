package storage

import (
	"context"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type EtcdStorage struct {
	client *clientv3.Client
}

// NewEtcdPlugin creates a new instance of EtcdStorage
func NewEtcdPlugin() *EtcdStorage {
	return &EtcdStorage{}
}

func (s *EtcdStorage) Name() string { return "storage" }

func (s *EtcdStorage) Initialize(config map[string]interface{}) error {
	endpointsRaw, ok := config["endpoints"].([]interface{})
	if !ok || len(endpointsRaw) == 0 {
		return fmt.Errorf("etcd endpoints not configured")
	}

	endpoints := make([]string, len(endpointsRaw))
	for i, ep := range endpointsRaw {
		endpoints[i], ok = ep.(string)
		if !ok {
			return fmt.Errorf("invalid endpoint type at index %d", i)
		}
	}

	cfg := clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	}

	client, err := clientv3.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create etcd client: %w", err)
	}

	s.client = client
	return nil
}

func (s *EtcdStorage) Get(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", key, err)
	}

	if len(resp.Kvs) == 0 {
		return nil, nil
	}

	return resp.Kvs[0].Value, nil
}

func (s *EtcdStorage) Set(key string, value []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.client.Put(ctx, key, string(value))
	if err != nil {
		return fmt.Errorf("failed to set key %s: %w", key, err)
	}

	return nil
}

func (s *EtcdStorage) Delete(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.client.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}

	return nil
}

func (s *EtcdStorage) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}
