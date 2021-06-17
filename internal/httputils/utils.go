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

package httputils

import (
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
)

// HTTP header constants.
const (
	AuthorizationHeader    = "Authorization"
	ContentTypeHeader      = "Content-Type"
	ContentTypeJSON        = "application/json"
	ContentTypeJSONUTF8    = "application/json;charset=utf-8"
	ContentTypeProblemJSON = "application/problem+json"
)

// ConsumeAndCloseResponseBody discards any remaining contents in an HTTP
// response body and closes it.
func ConsumeAndCloseResponseBody(r *http.Response) {
	_, _ = io.Copy(ioutil.Discard, r.Body)
	r.Body.Close()
}

// VerifyRequestContentType returns an error if the media type in the HTTP
// response Content-Type header, excluding any parameters, does not match the
// provided media type.
func VerifyRequestContentType(r *http.Request, t string) error {
	return verifyContentType(r.Header, t)
}

// VerifyResponseContentType returns an error if the media type in the HTTP
// response Content-Type header, excluding any parameters, does not match the
// provided media type.
func VerifyResponseContentType(r *http.Response, t string) error {
	return verifyContentType(r.Header, t)
}

// verifyContentType returns an error if the media type in the Content-Type
// header, excluding any parameters, does not match the provided media type.
func verifyContentType(h http.Header, t string) error {
	var mediaType, _, err = mime.ParseMediaType(h.Get(ContentTypeHeader))
	if err != nil {
		return fmt.Errorf("failed to parse HTTP response content type: %w", err)
	}

	if !strings.HasPrefix(mediaType, t) {
		return fmt.Errorf("got HTTP response content type %s, expected %s", mediaType, t)
	}

	return nil
}
