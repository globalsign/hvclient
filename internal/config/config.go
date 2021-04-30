/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package config

import (
	"encoding/json"
	"io/ioutil"
)

// Config contains settings from an HVClient configuration file.
type Config struct {

	// URL is the URL (including port) to the HVCA server.
	URL string `json:"url"`

	// APIKey is the client-specific API key used to login.
	APIKey string `json:"api_key"`

	// APISecret is the client-specific API secret used to login.
	APISecret string `json:"api_secret"`

	// CertFile is the path of the client certificate file.
	CertFile string `json:"cert_file"`

	// KeyFile is the path of the client key file.
	KeyFile string `json:"key_file"`

	// KeyPassphrase is the passphrase for the client key. If the key is not
	// encrypted, this should be set to the emptry string.
	KeyPassphrase string `json:"key_passphrase"`

	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool `json:"insecure_skip_verify"`

	// Timeout is the maximum time in seconds for an HVCA API request.
	Timeout int `json:"timeout"`
}

// NewFromFile creates a new Config object from a configuration file.
func NewFromFile(filename string) (*Config, error) {
	var err error

	var data []byte
	if data, err = ioutil.ReadFile(filename); err != nil {
		return nil, err
	}

	var newConfig *Config
	if err = json.Unmarshal(data, &newConfig); err != nil {
		return nil, err
	}

	return newConfig, nil
}
