package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
)

// This is the path the file will be saved at so there is only one place
// the file will be retrieved from and saved to, no matter what directory
// you run the command in on the command line.
var dir = fmt.Sprintf("%s/.local/share/signer", os.Getenv("HOME"))

// The name of the file that will be created or contain the saved key pair.
const keyfile = "keypair.txt"

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Please provide one argument that is 250 characters or less.")
		os.Exit(1)
	}

	input := os.Args[1]

	if len(input) > 250 {
		fmt.Println("Please provide one argument that is 250 characters or less.")
		os.Exit(1)
	}

	var (
		privKey *ecdsa.PrivateKey
		pubKey  string
	)

	filePath := fullPath(dir, keyfile)

	// Check the status of the file to see if there are errors with it.
	_, err := os.Stat(filePath)
	if err != nil {
		// If the file does not exist, run the function createSaveKey.
		if os.IsNotExist(err) {
			privKey, pubKey, err = createSaveKey(filePath)
			checkError(err)
		} else { // If any other error is returned besides "IsNotExist".
			checkError(err)
		}
	} else { // If there is no error, run the function useKey.
		privKey, pubKey, err = useKey(filePath)
		checkError(err)
	}

	output, err := sign(input, pubKey, privKey)
	checkError(err)

	fmt.Println(output)

}

// The fullPath function takes in a directory path as a string and the name of a
// file as a string and returns full path of the file as one string.
func fullPath(dir, name string) string {
	// This is used to make the directory of the file with Owner permissions only
	// if it does not exist currently.
	err := os.MkdirAll(dir, 0700)
	checkError(err)

	// Joins the directory and file name into one string and returns it.
	fullPath := path.Join(dir, name)
	return fullPath
}

// The createSaveKey function takes in the file path where you want to save the
// eventualy created key pair to in one string and returns an ECDSA private key,
// and the ECDSA public key in a PEM formatted string, or an error if there is one.
func createSaveKey(filePath string) (*ecdsa.PrivateKey, string, error) {
	// Create the file with Owner read/write permission, open it, and defer closing.
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()

	// Intialize variable privateKey as a new ECDSA private key then generate
	// the private key using the elliptic curve P521 and reading from random and
	// set it to privateKey.
	privateKey := new(ecdsa.PrivateKey)
	privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	// Intialize variable pubKey as a ECDSA public key type then set pubKey to
	// the Public Key that corresponds to the Private Key generated earlier (privateKey)
	var pubKey ecdsa.PublicKey
	pubKey = privateKey.PublicKey

	// The MarshalPKIXPublicKey function from the x509 package requires a pointer
	// to a public key(&pubKey) then serialises it to DER-encoded PKIX format
	// which is returned as a slice of bytes(pemPubSlice) or returns an error (err)
	pemPubSlice, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return nil, "", err
	}

	// Create PEM encoded structure(Block) with the form:
	/*
		-----BEGIN Type-----
		base64-encoded Bytes
		-----END Type-----
	*/
	// where Type = "PUBLIC KEY" and the bytes to be encoded to base64 are pemPubSlice
	var pemPubKey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pemPubSlice}

	// This sets the PEM block (pemPubKey) to a variable (encPubPem) to be used later.
	encPubPem := pem.EncodeToMemory(pemPubKey)

	// The next section encodes the private key to PEM format just like the public
	// key was encoded earlier and then it is set to a variable as well.
	pemPrivSlice, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, "", err
	}
	var pemPrivKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pemPrivSlice}

	encPrivPem := pem.EncodeToMemory(pemPrivKey)

	// This writes the PEM encoded private key and public key as strings to the
	// file created earlier.
	file.WriteString(string(encPrivPem))
	file.WriteString(string(encPubPem))

	// Return the ECDSA private key created earlier, the string of the PEM encoded
	// public key, and no error.
	return privateKey, string(encPubPem), nil
}

// The useKey function takes in the file path of the file where the private and
// public key pair are saved in PEM format and returns an ECDSA private key and
// the ECDSA public key in a PEM formatted string, or an error if there is one.
func useKey(filePath string) (*ecdsa.PrivateKey, string, error) {
	// Reads the entire file and saves the contents as a string or returns error.
	contents, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, "", err
	}

	// Decodes the contents into 2 variables (block & rest); setting block to the
	// first PEM block contained in contents.
	// Here we are assuming the contents of the file are an ECDSA private key PEM
	// block and the corresponding ECDSA public key PEM block as that is how the
	// file was originally created.  A check could be added later to make sure
	// the contents of (rest) is a valid *ecdsa.PublicKey.
	block, rest := pem.Decode(contents)

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}

	publicKey := string(rest)

	return privateKey, publicKey, nil
}

// The sign function takes in the input as a string, the public key as a string
// of PEM format, and the ECDSA private key.  It returns a JSON formatted string
// containing the input message, the Base64 encoded signature of the message,
// and the ECDSA public key in PEM format or an error if there is one.
func sign(input, pubKey string, privKey *ecdsa.PrivateKey) (string, error) {

	// Create an ECDSA signature using the given private key, the SHA256 of the
	// given input, and reading from random or return an error.
	r, s, err := ecdsa.Sign(rand.Reader, privKey, shaSum(input))
	if err != nil {
		return "", err
	}

	// Encode the signature using ASN.1 format and set it to variable (sign) or
	// return an error.
	sign, err := asn1.Marshal(ecdsaSig{r, s})
	if err != nil {
		return "", err
	}

	// Convert the ASN.1 encoded signature to Base64 encoding and return it as
	// a string
	encSign := base64.StdEncoding.EncodeToString(sign)

	// Intialize an output struct and set the fields input string, the Base64
	// encoded signature string, and the public key (in PEM format) string.
	var out output
	out.Message = input
	out.Signature = encSign
	out.PubKey = pubKey

	// JSON format the struct (out) and make it so the fields are tabbed in
	outJSON, err := json.MarshalIndent(out, "", "    ")
	if err != nil {
		return "", err
	}

	// Return the string of the JSON formatted struct and no error.
	return string(outJSON), nil
}

// The shaSum function takes the input as a string and returns a SHA256 digest
// of the input.
func shaSum(input string) []byte {
	// The input is converted into a slice of bytes, runs a SHA256 hash algorithm,
	// then returns the SHA256 checksum of that slice, and returns it as an array
	// of [size]byte (inputShaSum).
	inputShaSum := sha256.Sum256([]byte(input))

	// Make a new slice of bytes with length equal to the length of inputShaSum
	inputSlice := make([]byte, len(inputShaSum))

	// At each index in inputShaSum, set the value at the same index in inputSlice
	// equal to the value at that index in inputShaSum
	// inputSlice becomes a slice of bytes with the same data as inputShaSum and
	// is still a cryptographic hash
	for i := range inputShaSum {
		inputSlice[i] = inputShaSum[i]
	}

	// Return the SHA256 digest of the input (inputSlice)
	return inputSlice
}

// The checkError function takes in an error and checks if it is not equal to
// nil, and if it is not then it logs the error to standard out and exits the
// program with a non-zero code.
func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// The output struct is used to hold 3 strings and provide JSON specific tags
// for each string.
type output struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PubKey    string `json:"pubkey"`
}

// The ecdsaSig struct is used to hold 2 *big.Int so than when a ECDSA signature
// is created, the 2 returned *big.Int can be stored to verify the signature if
// needed.
type ecdsaSig struct {
	R, S *big.Int
}
