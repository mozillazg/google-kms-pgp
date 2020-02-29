// Copyright © 2018 Heptio
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kmssigner implements a crypto.Signer backed by Google Cloud KMS.
package kmssigner

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/pkg/errors"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

const (
	RsaPkcs1Sha256 = "RSA_PKCS1_SHA_256"
	Https          = "HTTPS"
)

// Signer extends crypto.Signer to provide more key metadata.
type Signer interface {
	crypto.Signer
	RSAPublicKey() *rsa.PublicKey
	CreationTime() time.Time
}

// New returns a crypto.Signer backed by the named Alibaba Cloud KMS key.
func New(api *kms.Client, keyID, keyVersionID string) (Signer, error) {
	reqDescribeKey := kms.CreateDescribeKeyRequest()
	reqDescribeKey.Scheme = Https
	reqDescribeKey.KeyId = keyID
	metadata, err := api.DescribeKey(reqDescribeKey)
	if err != nil {
		return nil, errors.WithMessage(err, "could not get key version from Alibaba Cloud KMS API")
	}
	keyMetadata := metadata.KeyMetadata
	if keyMetadata.KeyUsage != "SIGN/VERIFY" {
		return nil, errors.Errorf("key usage should be SIGN/VERIFY instead of %s", keyMetadata.KeyUsage)
	}
	switch keyMetadata.KeySpec {
	case "RSA_2048":
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", keyMetadata.KeySpec)
	}

	creationTime, err := time.Parse(time.RFC3339, keyMetadata.CreationDate)
	if err != nil {
		return nil, errors.WithMessage(err, "could not parse key creation timestamp")
	}

	reqGetPublicKey := kms.CreateGetPublicKeyRequest()
	reqGetPublicKey.Scheme = Https
	reqGetPublicKey.KeyId = keyID
	reqGetPublicKey.KeyVersionId = keyVersionID
	resp, err := api.GetPublicKey(reqGetPublicKey)
	if err != nil {
		return nil, errors.WithMessage(err, "could not get public key from Alibaba Cloud KMS API")
	}
	block, _ := pem.Decode([]byte(resp.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.WithMessage(err, "could not decode public key PEM")
	}
	pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "could not parse public key")
	}
	pubkeyRSA, ok := pubkey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.WithMessage(err, "public key was not an RSA key as expected")
	}
	return &kmsSigner{
		api:          api,
		keyID:        keyID,
		keyVersionID: keyVersionID,
		pubkey:       *pubkeyRSA,
		creationTime: creationTime,
	}, nil
}

type kmsSigner struct {
	api          *kms.Client
	keyID        string
	keyVersionID string
	pubkey       rsa.PublicKey
	creationTime time.Time
}

func (k *kmsSigner) Public() crypto.PublicKey {
	return k.pubkey
}

func (k *kmsSigner) RSAPublicKey() *rsa.PublicKey {
	return &k.pubkey
}

func (k *kmsSigner) CreationTime() time.Time {
	return k.creationTime
}

func (k *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("input digest must be valid SHA-256 hash")
	}

	reqSign := kms.CreateAsymmetricSignRequest()
	reqSign.Scheme = Https
	reqSign.KeyId = k.keyID
	reqSign.KeyVersionId = k.keyVersionID
	reqSign.Digest = base64.StdEncoding.EncodeToString(digest)
	reqSign.Algorithm = RsaPkcs1Sha256
	sig, err := k.api.AsymmetricSign(reqSign)
	if err != nil {
		return nil, errors.Wrap(err, "error signing with Alibaba Cloud KMS")
	}
	res, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid Base64 response from Ailbaba Cloud KMS AsymmetricSign endpoint")
	}
	return res, nil
}
