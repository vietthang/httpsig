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
	"fmt"
	"net/http"
	"strings"
)

// BuildSignatureString constructs a signature string following section 2.3
func BuildSignatureString(req Request, headers []string) string {
	if len(headers) == 0 {
		headers = []string{"date"}
	}
	values := make([]string, 0, len(headers))
	for _, h := range headers {
		switch h {
		case "(request-target)":
			values = append(values, fmt.Sprintf("%s: %s %s",
				h, strings.ToLower(req.Method()), req.Path()))
		case "host":
			values = append(values, fmt.Sprintf("%s: %s", h, req.Host()))
		default:
			for _, value := range req.Header()[http.CanonicalHeaderKey(h)] {
				values = append(values,
					fmt.Sprintf("%s: %s", h, strings.TrimSpace(value)))
			}
		}
	}
	return strings.Join(values, "\n")
}

// BuildSignatureData is a convenience wrapper around BuildSignatureString that
// returns []byte instead of a string.
func BuildSignatureData(req Request, headers []string) []byte {
	return []byte(BuildSignatureString(req, headers))
}

func toHMACKey(key interface{}) []byte {
	switch k := key.(type) {
	case []byte:
		return k
	default:
		return nil
	}
}

func unsupportedAlgorithm(a Algorithm) error {
	return fmt.Errorf("key does not support algorithm %q", a.Name())
}

type Request interface {
	Header() http.Header
	Method() string
	Path() string
	Host() string
}
