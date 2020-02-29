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

// Package main implements a PGP-compatible signing interface backed by Google KMS.
package main

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"

	"github.com/heptiolabs/google-kms-pgp/kmssigner"
)

const envRegionID = "ALIBABA_CLOUD_REGION_ID"

var (
	cfg = packet.Config{}
)

type options struct {
	export            bool
	armor             bool
	keyID             string
	keyVersionID      string
	detachedSignature bool
	sign              bool
	clearSign         bool
	input             string
	output            string

	kms *kms.Client
}

func main() {
	var options options

	// common options
	pflag.BoolVarP(&options.armor, "armor", "a", options.armor, "output in ascii armor")
	pflag.StringVarP(&options.output, "output", "o", options.output, "write output to file (use - for stdout)")

	// export options
	pflag.BoolVar(&options.export, "export", options.export, "export public key")

	// sign options
	pflag.BoolVarP(&options.sign, "sign", "s", options.sign, "sign a message")
	pflag.BoolVar(&options.clearSign, "clearsign", options.sign, "sign a message in clear text")
	pflag.StringVarP(&options.keyID, "key-id", "", options.keyID, "id of key to sign with")
	pflag.StringVar(&options.keyVersionID, "key-version-id", options.keyVersionID, "version id of key to sign with")
	pflag.BoolVarP(&options.detachedSignature, "detach-sign", "b", options.detachedSignature, "make a detached signature")

	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()

	if options.keyID == "" || options.keyVersionID == "" {
		fmt.Fprintln(os.Stderr, "both key-id and key-version-id are required")
		os.Exit(1)
	}

	regionID := os.Getenv(envRegionID)
	if regionID == "" {
		fmt.Fprintf(os.Stderr, "please set region id via setting env %s\n", envRegionID)
		os.Exit(1)
	}
	client, err := kms.NewClientWithProvider(regionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create Alibaba Cloud KMS client: %s\n", err)
		os.Exit(1)
	}
	options.kms = client

	switch {
	case options.export:
		err = runExport(options)
	case options.sign, options.clearSign, options.detachedSignature:
		args := pflag.Args()
		if len(args) == 1 {
			options.input = args[0]
		}
		err = runSign(options)
	default:
		usage("--export|--sign|--clearsign")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage(msg string) {
	fmt.Fprintf(os.Stderr, "usage: %s %s\n", os.Args[0], msg)
	pflag.CommandLine.PrintDefaults()
	os.Exit(1)
}

func runExport(options options) error {
	entity, err := getEntity(options)
	if err != nil {
		return err
	}

	uid := packet.NewUserId(fmt.Sprintf("%s:%s", options.keyID, options.keyVersionID), "", "")
	if uid == nil {
		return errors.Errorf("could not generate PGP user ID metadata")
	}

	isPrimary := true
	entity.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: entity.PrimaryKey.CreationTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         cfg.Hash(),
			IsPrimaryId:  &isPrimary,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &entity.PrimaryKey.KeyId,
		},
	}
	if err := entity.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, entity.PrimaryKey, entity.PrivateKey, &cfg); err != nil {
		return errors.WithMessage(err, "could not self-sign public key")
	}

	var out io.Writer

	switch options.output {
	case "", "-":
		out = os.Stdout
	default:
		outFile, err := os.Create(options.output)
		if err != nil {
			return errors.Wrapf(err, "unable to create output file %q", options.output)
		}
		defer outFile.Close()
		out = outFile
	}

	if options.armor {
		armoredWriter, err := armor.Encode(out, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			return errors.Wrap(err, "could not create ASCII-armored writer")
		}

		if err := entity.Serialize(armoredWriter); err != nil {
			return errors.Wrap(err, "could not serialize public key")
		}

		if err := armoredWriter.Close(); err != nil {
			return errors.Wrap(err, "error closing ASCII-armored writer")
		}

		// Always add a blank line to the end of the raw output
		fmt.Fprintf(out, "\n")
	} else {
		if err := entity.Serialize(out); err != nil {
			return errors.Wrap(err, "could not serialize public key")
		}
	}

	return nil
}

func runSign(options options) error {
	entity, err := getEntity(options)
	if err != nil {
		return err
	}

	if options.output == "" {
		if options.detachedSignature || options.clearSign {
			options.output = options.input + ".asc"
		} else {
			options.output = options.input + ".gpg"
		}
	}

	var output io.Writer = os.Stdout
	var input io.Reader = os.Stdin

	if options.output != "-" {
		outputFile, err := os.Create(options.output)
		if err != nil {
			return err
		}
		defer outputFile.Close()
		output = outputFile
	}

	if options.input != "" {
		inputFile, err := os.Open(options.input)
		if err != nil {
			return err
		}
		defer inputFile.Close()
		input = inputFile
	}

	switch {
	case options.detachedSignature && options.armor:
		if err := openpgp.ArmoredDetachSign(output, entity, input, &cfg); err != nil {
			return err
		}
		fmt.Fprintf(output, "\n")
		return nil
	case options.detachedSignature && !options.armor:
		return openpgp.DetachSign(output, entity, input, &cfg)
	case !options.detachedSignature:
		// Set up an "identity" so we can control the hash algorithm
		hashIdSha256, ok := s2k.HashToHashId(crypto.SHA256)
		if !ok {
			return errors.New("unable to get pgp hash id for sha256")
		}
		entity.Identities["HACK"] = &openpgp.Identity{
			SelfSignature: &packet.Signature{
				PreferredHash: []uint8{
					hashIdSha256,
				},
			},
		}

		// If we're doing a real file, set up hints for it
		fileHints := &openpgp.FileHints{}
		if options.input != "" {
			fileHints.FileName = options.input
			fileInfo, err := os.Stat(options.input)
			if err != nil {
				return err
			}
			fileHints.ModTime = fileInfo.ModTime()
		}

		// Get ready to sign
		var (
			writeCloser io.WriteCloser
			addNewline  bool
		)
		if options.clearSign {
			addNewline = true
			writeCloser, err = clearsign.Encode(output, entity.PrivateKey, &cfg)
		} else {
			writeCloser, err = openpgp.Sign(output, entity, fileHints, &cfg)
		}
		if err != nil {
			return err
		}

		// Copy the data from input to writeCloser so it will perform signing
		_, copyErr := io.Copy(writeCloser, input)

		// Always try to close
		closeErr := writeCloser.Close()

		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if addNewline {
			fmt.Fprintf(output, "\n")
		}
		return nil
	}

	return nil
}

func getEntity(options options) (*openpgp.Entity, error) {
	// Initialize a crypto.Signer backed by the configured Cloud KMS key.
	signer, err := kmssigner.New(options.kms, options.keyID, options.keyVersionID)
	if err != nil {
		return nil, errors.Wrap(err, "could not get KMS signer")
	}

	// Create an openpgp Entity, which holds the PGP-related information about our key.
	entity := &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(signer.CreationTime(), signer.RSAPublicKey()),
		PrivateKey: packet.NewSignerPrivateKey(cfg.Now(), signer),
		Identities: make(map[string]*openpgp.Identity),
	}

	// The PubKeyAlgo defaults to packet.PubKeyAlgoRSASignOnly, and that doesn't work for RPM
	entity.PrivateKey.PubKeyAlgo = packet.PubKeyAlgoRSA

	// TODO: this may be a bug in the openpgp library? Without this, my signatures
	// end up with a key ID that doesn't match the primary key.
	entity.PrivateKey.KeyId = entity.PrimaryKey.KeyId

	return entity, nil
}
