package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

const keys = `
-----BEGIN PRIVATE KEY-----
MIHcAgEBBEIB/kovxHOfWyjhdDsZ7XDUU4JhsdUn4wgsfVImEEUu0Wow2s4rRwYT
eEMUhsO5nlD+4fy+guqKxq6Rd5A8wVE6ZySgBwYFK4EEACOhgYkDgYYABAA3tG0Q
34rW4wQYQVxnfnnjOEisHkPxjausB3Bjy+Jjok3yjiqURSYBy34LuvF2ZP8Uy/ZU
agBT7bzqG/vEvMBMLAHL2cvGEU2SsgcinxtdQeUDLNE02enqWscGxSKBj3FRkxoO
/BtRUd/N973408jHWnwyPL7Puh42yGcjZ9ivWhxtug==
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAN7RtEN+K1uMEGEFcZ3554zhIrB5D
8Y2rrAdwY8viY6JN8o4qlEUmAct+C7rxdmT/FMv2VGoAU+286hv7xLzATCwBy9nL
xhFNkrIHIp8bXUHlAyzRNNnp6lrHBsUigY9xUZMaDvwbUVHfzfe9+NPIx1p8Mjy+
z7oeNshnI2fYr1ocbbo=
-----END PUBLIC KEY-----
`

func keyContents() (*ecdsa.PrivateKey, string) {
	block, rest := pem.Decode([]byte(keys))

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	checkError(err)

	publicKey := string(rest)

	return privateKey, publicKey
}

func TestMessage(t *testing.T) {
	privKey, pubKey := keyContents()
	signed, err := sign("Hello", pubKey, privKey)
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}

	var out output

	err = json.Unmarshal([]byte(signed), &out)
	if err != nil {
		t.Errorf("Error unmarshaling json: %v", err)
	}

	if out.Message != "Hello" {
		t.Error("Input message does not equal output message.")
	}
}

func TestValidSignature(t *testing.T) {
	privKey, pubKey := keyContents()
	signed, err := sign("Hello", pubKey, privKey)
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}

	var out output

	err = json.Unmarshal([]byte(signed), &out)
	if err != nil {
		t.Errorf("Error unmarshaling json: %v", err)
	}

	decSign, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		t.Errorf("Error decoding signature: %v", err)
	}

	var sign ecdsaSig

	_, err = asn1.Unmarshal(decSign, &sign)
	if err != nil {
		t.Errorf("Error unmarshaling decoded signature: %v", err)
	}

	if !ecdsa.Verify(&privKey.PublicKey, shaSum("Hello"), sign.R, sign.S) {
		t.Error("The signature is not valid.")
	}
}

func TestPubKey(t *testing.T) {
	privKey, pubKey := keyContents()
	signed, err := sign("Hello", pubKey, privKey)
	if err != nil {
		t.Errorf("Error signing message: %v", err)
	}

	var out output

	err = json.Unmarshal([]byte(signed), &out)
	if err != nil {
		t.Errorf("Error unmarshaling json: %v", err)
	}

	if out.PubKey != pubKey {
		t.Error("Output public key does not match the input public key.")
	}
}
