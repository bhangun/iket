package config

import (
	"crypto/rsa"
	"encoding/pem"
	"io/ioutil"

	coreerrors "github.com/bhangun/iket/pkg/core/errors"
	"github.com/golang-jwt/jwt/v4"
)

// loadRSAPublicKey loads an RSA public key from a PEM file
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, coreerrors.NewConfigError("invalid PEM public key", nil)
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
