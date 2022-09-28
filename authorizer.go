package hvclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/globalsign/hvclient/internal/httputils"
)

// loginRequest is an HVCA POST /login request body.
type loginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// loginResponse is an HVCA POST /login response body.
type loginResponse struct {
	AccessToken string `json:"access_token"`
}

const (
	// tokenLifetime is the assumed lifetime of an HVCA authentication token.
	// The HVCA API appears to not return any information confirming the
	// lifetime of the token, but at the time of writing the API documentation
	// states it to be 10 minutes. We here set it to nine minutes just to
	// leave some headroom.
	tokenLifetime = time.Minute * 9
)

type Authorizer interface {
	Login(ctx context.Context) error
	Token(ctx context.Context) string
	HasExpired(ctx context.Context) bool
}

type apiAuthorizer struct {
	Endpoint        string
	HTTPClient      *http.Client
	Key             string
	Secret          string
	SSLClientSerial string

	token     string
	lastLogin time.Time
	tokenMtx  sync.RWMutex
}

// Login acquires a token that can be used to authorize HVCA requests.
func (aa *apiAuthorizer) Login(ctx context.Context) error {
	err := aa.login(ctx)
	if err != nil {
		aa.tokenReset()
		return err
	}
	return nil
}

// Token returns the authorization token acquired from login.
func (aa *apiAuthorizer) Token(ctx context.Context) string {
	aa.tokenMtx.RLock()
	defer aa.tokenMtx.RUnlock()

	return aa.token
}

// HasExpired returns true if the authorizer has expired and needs to login once more.
func (aa *apiAuthorizer) HasExpired(ctx context.Context) bool {
	aa.tokenMtx.RLock()
	defer aa.tokenMtx.RUnlock()

	return time.Since(aa.lastLogin) > tokenLifetime
}

func (aa *apiAuthorizer) login(ctx context.Context) error {
	var loginRequest = loginRequest{
		APIKey:    aa.Key,
		APISecret: aa.Secret,
	}

	var body io.Reader
	data, err := json.Marshal(&loginRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal login request body: %w", err)
	}
	body = bytes.NewReader(data)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, aa.Endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create new HTTP request: %w", err)
	}

	request.Header.Set("X-SSL-Client-Serial", aa.SSLClientSerial)
	request.Header.Set(httputils.ContentTypeHeader, httputils.ContentTypeJSONUTF8)

	response, err := aa.HTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	if response.StatusCode != http.StatusOK {
		return newAPIError(response)
	}

	// Read and unmarshal the response body.
	data, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	var lr loginResponse
	err = json.Unmarshal(data, &lr)
	if err != nil {
		return fmt.Errorf("failed to unmarshal HTTP response body: %w", err)
	}

	aa.tokenSet(lr.AccessToken)

	return nil
}

// tokenSet sets the token value and the last login time with the current time.
func (aa *apiAuthorizer) tokenSet(token string) {
	aa.tokenMtx.Lock()
	defer aa.tokenMtx.Unlock()

	aa.token = token
	aa.lastLogin = time.Now()
}

// tokenReset initializes the token and last login time with zero values.
func (aa *apiAuthorizer) tokenReset() {
	aa.tokenMtx.Lock()
	defer aa.tokenMtx.Unlock()

	aa.token = ""
	aa.lastLogin = time.Time{}
}
