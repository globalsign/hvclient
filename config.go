/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/globalsign/hvclient/internal/config"
	"github.com/globalsign/hvclient/internal/pkifile"
)

// Config is a configuration object for an HVCA client.
type Config struct {

	// URL is the URL of the HVCA service, including any version number.
	URL string

	// Version is the major version number of the HVCA service located at
	// the specified URL. When creating a configuration object directly, this
	// field can be omitted, but it will be populated when creating a
	// configuration object from a configuration file.
	version int

	// url is a parsed form of the URL.
	url *url.URL

	// TLSCert is the certificate to use for mutual TLS authentication to HVCA,
	// provided by GlobalSign when the HVCA account was set up.
	TLSCert *x509.Certificate

	// TLSKey is the private key corresponding to the public key provided to
	// GlobalSign when the HVCA account was set up. This is used for mutual TLS
	// authentication with HVCA, and is NOT related to any public key to be
	// included in a certificate request.
	TLSKey interface{}

	// APIKey is the API key for the HVCA account, provided by GlobalSign when
	// the account was set up.
	APIKey string

	// APISecret is the API secret for the HVCA account, provided by GlobalSign
	// when the account was set up.
	APISecret string

	// TLSRoots contain the root certificates used to validate HVCA's TLS
	// server certificate.
	TLSRoots *x509.CertPool

	// Timeout is the number of seconds to wait before cancelling an HVCA API
	// request. If this is omitted or set to zero, a reasonable default will
	// be used.
	Timeout time.Duration
}

var defaultTimeout = time.Second * 60

// Validate returns an error if any fields in the configuration object are
// missing or malformed. It also calculates a default timeout, if the Timeout
// field is zero.
func (c *Config) Validate() error {
	// Build up the URL for accessing the HVCA system. We're anticipating versioning
	// and the possibility of supporting both v2 and future versions, but since only
	// v2 is live right now, we just return with an error for any other specified version.

	if c.URL == "" {
		return errors.New("no URL specified")
	}

	var err error
	if c.url, err = url.Parse(c.URL); err != nil {
		return err
	}

	var versionstring = filepath.Base(c.url.Path)

	switch versionstring {
	case "v2":
		c.version = 2
	default:
		return fmt.Errorf("unsupported HVCA version: %s", versionstring)
	}

	// Calculate default timeout.

	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}

	// Check TLS key and certificate are present.

	if c.APIKey == "" {
		return errors.New("no API key provided")
	}

	if c.APISecret == "" {
		return errors.New("no API secret provided")
	}

	if c.TLSKey == nil {
		return errors.New("no private key provided")
	}

	if c.TLSCert == nil {
		return errors.New("no mTLS certificate provided")
	}

	return nil
}

// NewConfigFromFile creates a new HVCA client configuration object from
// a configuration file.
//
// The configuration file is JSON-encoded and should match the following
// format:
//
//     {
//         "url": "https://emea.api.hvca.globalsign.com:8443/v2",
//         "api_key": "value_of_api_key",
//         "api_secret": "value_of_api_secret",
//         "cert_file": "/path/to/mTLS/certificate.pem",
//         "key_file": "/path/to/mTLS/private_key.pem",
//         "key_passphrase": "passphrase",
//         "timeout": 60
//     }
//
// The key_passphrase field may be omitted in the unlikely event the private
// key file is not encrypted. The timeout field may be omitted, and a
// reasonable default timeout will be applied.
func NewConfigFromFile(filename string) (*Config, error) {
	var fileconf *config.Config
	var err error

	if fileconf, err = config.NewFromFile(filename); err != nil {
		return nil, err
	}

	var newconf = &Config{
		URL:       fileconf.URL,
		APIKey:    fileconf.APIKey,
		APISecret: fileconf.APISecret,
		Timeout:   time.Second * time.Duration(fileconf.Timeout),
	}

	// Get mTLS private key from file.

	if newconf.TLSKey, err = pkifile.PrivateKeyFromFileWithPassword(fileconf.KeyFile, fileconf.KeyPassphrase); err != nil {
		return nil, fmt.Errorf("couldn't get mTLS private key: %v", err)
	}

	// Get mTLS certificate from file.

	if newconf.TLSCert, err = pkifile.CertFromFile(fileconf.CertFile); err != nil {
		return nil, fmt.Errorf("couldn't get mTLS certificate: %v", err)
	}

	if err = newconf.Validate(); err != nil {
		return nil, err
	}

	return newconf, nil
}

// UnmarshalJSON parses a JSON encoded configuration and stores the result
// in the object.
func (c *Config) UnmarshalJSON(b []byte) error {
	var jsonConfig *config.Config
	var err error

	if err = json.Unmarshal(b, &jsonConfig); err != nil {
		return err
	}

	var newconf = Config{
		URL:       jsonConfig.URL,
		APIKey:    jsonConfig.APIKey,
		APISecret: jsonConfig.APISecret,
		Timeout:   time.Second * time.Duration(jsonConfig.Timeout),
	}

	// Get mTLS private key from file.

	if newconf.TLSKey, err = pkifile.PrivateKeyFromFileWithPassword(jsonConfig.KeyFile, jsonConfig.KeyPassphrase); err != nil {
		return fmt.Errorf("couldn't get mTLS private key: %v", err)
	}

	// Get mTLS certificate from file.

	if newconf.TLSCert, err = pkifile.CertFromFile(jsonConfig.CertFile); err != nil {
		return fmt.Errorf("couldn't get mTLS certificate: %v", err)
	}

	if err = newconf.Validate(); err != nil {
		return err
	}

	*c = newconf

	return nil
}
