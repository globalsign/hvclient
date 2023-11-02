/*
Copyright (c) 2019-2021 GMO GlobalSign Pte. Ltd.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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
	"github.com/globalsign/hvclient/internal/pki"
)

// Config is a configuration object for an HVCA client.
type Config struct {
	// URL is the URL of the HVCA service, including any version number.
	URL string

	// version is the major version number of the HVCA service located at
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
	// server certificate. If nil, the system pool will be used.
	TLSRoots *x509.CertPool

	// ExtraHeaders contains custom HTTP request headers to be passed to the
	// HVCA server with each request.
	ExtraHeaders map[string]string

	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool

	// Timeout is the number of seconds to wait before cancelling an HVCA API
	// request. If this is omitted or set to zero, a reasonable default will
	// be used.
	Timeout time.Duration
}

// ClientProfile is a configuration object for HVCA client and contains
// a Config field and a token field
type ClientProfile struct {
	// Configuration
	Config *Config

	// User Token
	Token string
}

const (
	// Default version is assumed if the URL in the configuration file does
	// not contain a version number.
	defaultVersion = 2
)

var defaultTimeout = time.Second * 60

// Validate returns an error if any fields in the configuration object are
// missing or malformed. It also calculates a default timeout, if the Timeout
// field is zero.
func (c *Config) Validate() error {
	// Build up the URL for accessing the HVCA system. We're anticipating versioning
	// and the possibility of supporting both v2 and future versions, but since only
	// v2 is live right now, we just assume it if the version number is unrecognized.
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
		c.version = defaultVersion
	}

	// Calculate default timeout.
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}

	// Ensure API key and secret were provided.
	if c.APIKey == "" {
		return errors.New("no API key provided")
	}

	if c.APISecret == "" {
		return errors.New("no API secret provided")
	}

	// Check TLS key and certificate are either both present, or both absent.
	if c.TLSKey == nil && c.TLSCert != nil {
		return errors.New("mTLS certificate provided but mTLS private key not provided")
	} else if c.TLSKey != nil && c.TLSCert == nil {
		return errors.New("mTLS certificate not provided but mTLS private key provided")
	}

	return nil
}

// NewConfigFromFile creates a new HVCA client configuration object from
// a configuration file.
func NewConfigFromFile(filename string) (*Config, error) {
	var fileconf, err = config.NewFromFile(filename)
	if err != nil {
		return nil, err
	}

	var newconf = &Config{
		URL:                fileconf.URL,
		APIKey:             fileconf.APIKey,
		APISecret:          fileconf.APISecret,
		ExtraHeaders:       fileconf.ExtraHeaders,
		InsecureSkipVerify: fileconf.InsecureSkipVerify,
		Timeout:            time.Second * time.Duration(fileconf.Timeout),
	}

	// Get mTLS private key from file, if provided.
	if fileconf.KeyFile != "" {
		if newconf.TLSKey, err = pki.PrivateKeyFromFileWithPassword(fileconf.KeyFile, fileconf.KeyPassphrase); err != nil {
			return nil, fmt.Errorf("couldn't get mTLS private key: %v", err)
		}
	}

	// Get mTLS certificate from file.
	if fileconf.CertFile != "" {
		if newconf.TLSCert, err = pki.CertFromFile(fileconf.CertFile); err != nil {
			return nil, fmt.Errorf("couldn't get mTLS certificate: %v", err)
		}
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
	var err = json.Unmarshal(b, &jsonConfig)
	if err != nil {
		return err
	}

	var newconf = Config{
		URL:                jsonConfig.URL,
		APIKey:             jsonConfig.APIKey,
		APISecret:          jsonConfig.APISecret,
		ExtraHeaders:       jsonConfig.ExtraHeaders,
		InsecureSkipVerify: jsonConfig.InsecureSkipVerify,
		Timeout:            time.Second * time.Duration(jsonConfig.Timeout),
	}

	// Get mTLS private key from file.
	if jsonConfig.KeyFile != "" {
		if newconf.TLSKey, err = pki.PrivateKeyFromFileWithPassword(
			jsonConfig.KeyFile, jsonConfig.KeyPassphrase); err != nil {
			return fmt.Errorf("couldn't get mTLS private key: %v", err)
		}
	}

	// Get mTLS certificate from file.
	if jsonConfig.CertFile != "" {
		if newconf.TLSCert, err = pki.CertFromFile(jsonConfig.CertFile); err != nil {
			return fmt.Errorf("couldn't get mTLS certificate: %v", err)
		}
	}

	if err = newconf.Validate(); err != nil {
		return err
	}

	*c = newconf

	return nil
}
