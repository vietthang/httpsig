// Copyright (C) 2017 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpsig

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type Verifier struct {
	algorithms      []Algorithm
	keyGetter       KeyGetter
	requiredHeaders []string
}

func NewVerifier(keyGetter KeyGetter, algorithms []Algorithm) *Verifier {
	if len(algorithms) == 0 {
		algorithms = []Algorithm{
			HMACSHA256,
			RSASHA1,
			RSASHA256,
			ECDSASHA1,
			ECDSASHA256,
		}
	}
	v := &Verifier{
		algorithms: algorithms,
		keyGetter:  keyGetter,
	}
	v.SetRequiredHeaders(nil)
	return v
}

func (v *Verifier) RequiredHeaders() []string {
	return append([]string{}, v.requiredHeaders...)
}

func (v *Verifier) SetRequiredHeaders(headers []string) {
	if len(headers) == 0 {
		headers = []string{"date"}
	}
	requiredHeaders := make([]string, 0, len(headers))
	for _, h := range headers {
		requiredHeaders = append(requiredHeaders, strings.ToLower(h))
	}
	v.requiredHeaders = requiredHeaders
}

func (v *Verifier) Verify(req *http.Request) error {
	// retrieve and validate params from the request
	params := getParamsFromAuthHeader(req)
	if params == nil {
		return fmt.Errorf("no params present")
	}
	if params.KeyID == "" {
		return fmt.Errorf("keyId is required")
	}
	if params.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if len(params.Signature) == 0 {
		return fmt.Errorf("signature is required")
	}
	if len(params.Headers) == 0 {
		params.Headers = []string{"date"}
	}

header_check:
	for _, requiredHeader := range v.requiredHeaders {
		for _, header := range params.Headers {
			if strings.ToLower(requiredHeader) == strings.ToLower(header) {
				continue header_check
			}
		}
		return fmt.Errorf("missing required header in signature %q", requiredHeader)
	}

	// calculate signature string for request
	sigData := BuildSignatureData(req, params.Headers)

	// look up key based on keyId
	key := v.keyGetter.GetKey(params.KeyID)
	if key == nil {
		return fmt.Errorf("no key with id %q", params.KeyID)
	}

	found := false
	for _, algorithm := range v.algorithms {
		if algorithm.Name() == params.Algorithm {
			found = true
			if err := algorithm.Verify(key, sigData, params.Signature); err != nil {
				return err
			}
		}
	}
	if !found {
		return fmt.Errorf("unsupported algorithm %s", params.Algorithm)
	}

	return nil
}

// paramRE scans out recognized parameter keypairs. accepted values are those
// that are quoted
var paramRE = regexp.MustCompile(`(?U)\s*([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*"(.*)"\s*`)

type Params struct {
	KeyID     string
	Algorithm string
	Headers   []string
	Signature []byte
}

func getParamsFromAuthHeader(req *http.Request) *Params {
	return getParams(req, "Authorization", "Signature ")
}

func getParams(req *http.Request, header, prefix string) *Params {
	values := req.Header[http.CanonicalHeaderKey(header)]
	// last well-formed parameter wins
	for i := len(values) - 1; i >= 0; i-- {
		value := values[i]
		if prefix != "" {
			if trimmed := strings.TrimPrefix(value, prefix); trimmed != value {
				value = trimmed
			} else {
				continue
			}
		}

		matches := paramRE.FindAllStringSubmatch(value, -1)
		if matches == nil {
			continue
		}

		params := Params{}
		// malformed paramaters get ignored.
		for _, match := range matches {
			switch match[1] {
			case "keyId":
				params.KeyID = match[2]
			case "algorithm":
				if algorithm, ok := parseAlgorithm(match[2]); ok {
					params.Algorithm = algorithm
				}
			case "headers":
				if headers, ok := parseHeaders(match[2]); ok {
					params.Headers = headers
				}
			case "signature":
				if signature, ok := parseSignature(match[2]); ok {
					params.Signature = signature
				}
			}
		}
		return &params
	}

	return nil
}

// parseAlgorithm parses recognized algorithm values
func parseAlgorithm(s string) (algorithm string, ok bool) {
	s = strings.TrimSpace(s)
	switch s {
	case "rsa-sha1", "rsa-sha256", "hmac-sha256":
		return s, true
	}
	return "", false
}

// parseHeaders parses a space separated list of header values.
func parseHeaders(s string) (headers []string, ok bool) {
	for _, header := range strings.Split(s, " ") {
		if header != "" {
			headers = append(headers, strings.ToLower(header))
		}
	}
	return headers, true
}

func parseSignature(s string) (signature []byte, ok bool) {
	signature, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return signature, true
}
