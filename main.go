package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	cmdMap = map[string]func() error {
		"gen-key": genKey,
	}

	args []string
	algorithm string
)

func main() {
	flag.Parse()
	args = flag.Args()
}

func genKey() error {
	os.Stat()
	return nil
}

func genPrivateKey(keySize int) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	privateKeyData := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBlock := pem.Block {
		Type: "ACOVIA PRIVATE KEY",
		Bytes: privateKeyData,
	}

	return pem.EncodeToMemory(&pemBlock), nil
}