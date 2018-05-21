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
	"crypto"
	"crypto/ecdsa"
	"math/big"
	"encoding/asn1"
	"github.com/pkg/errors"
	"crypto/rand"
)

// ECDSASHA1 implements ECDSA signatures over a SHA1 digest
var ECDSASHA1 Algorithm = ecdsaSha1{}

type ecdsaSha1 struct{}

func (a ecdsaSha1) Name() string {
	return "ecdsa-sha1"
}

func (a ecdsaSha1) Sign(key interface{}, data []byte) ([]byte, error) {
	k := toECDSAPrivateKey(key)
	if k == nil {
		return nil, unsupportedAlgorithm(a)
	}
	return ECDSASign(k, crypto.SHA1, data)
}

func (a ecdsaSha1) Verify(key interface{}, data, sig []byte) error {
	k := toECDSAPublicKey(key)
	if k == nil {
		return unsupportedAlgorithm(a)
	}
	return ECDSAVerify(k, crypto.SHA1, data, sig)
}

// ECDSASHA256 implements ECDSA signatures over a SHA256 digest
var ECDSASHA256 Algorithm = ecdsaSha256{}

type ecdsaSha256 struct{}

func (ecdsaSha256) Name() string {
	return "ecdsa-sha256"
}

func (a ecdsaSha256) Sign(key interface{}, data []byte) ([]byte, error) {
	k := toECDSAPrivateKey(key)
	if k == nil {
		return nil, unsupportedAlgorithm(a)
	}
	return ECDSASign(k, crypto.SHA256, data)
}

func (a ecdsaSha256) Verify(key interface{}, data, sig []byte) error {
	k := toECDSAPublicKey(key)
	if k == nil {
		return unsupportedAlgorithm(a)
	}
	return ECDSAVerify(k, crypto.SHA256, data, sig)
}

func toECDSAPrivateKey(key interface{}) *ecdsa.PrivateKey {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k
	default:
		return nil
	}
}

func toECDSAPublicKey(key interface{}) *ecdsa.PublicKey {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return k
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// ECDSASign signs a digest of the data hashed using the provided hash
func ECDSASign(key *ecdsa.PrivateKey, hash crypto.Hash, data []byte) ([]byte, error) {
	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return key.Sign(rand.Reader, h.Sum(nil), nil)
}

// ECDSAVerify verifies a signed digest of the data hashed using the provided hash
func ECDSAVerify(key *ecdsa.PublicKey, hash crypto.Hash, data, sig []byte) (err error) {
	var signature struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &signature); err != nil {
		return err
	}

	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return err
	}

	if !ecdsa.Verify(key, h.Sum(nil), signature.R, signature.S) {
		return errors.New("invalid signature")
	}

	return nil
}
