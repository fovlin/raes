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
	"path"
)

var (
	cmdMap = map[string]func() error{
		"gen-key": createKey,
		"enc":     enc,
	}

	args           []string
	algorithm      string
	privateKeyPath string
	publicKeyPath  string
	privateKeyPathArg string
	publicKeyPathArg  string
	privatekeyName string = "raes_key"
	publicKeyName  string = "raes_key.pub"
	keySize        int    = 4096
	keyType        string = "PRIVATE KEY"
	keyDirName            = ".raes"
)

func main() {
	parseFlag()

	if len(args) < 1 {
		log.Fatalln("command missing")
	}

	cmd := args[0]

	function, ok := cmdMap[cmd]
	if !ok {
		log.Fatalln("unknown command:", cmd)
	}

	err := function()
	if err != nil {
		log.Fatalln(err)
	}
}

func parseFlag() {
	flag.StringVar(&keyType, "t", keyType, "key type")
	flag.IntVar(&keySize, "s", keySize, "key size")
	flag.StringVar(&privateKeyPathArg, "d", privateKeyPathArg, "public key file")
	flag.StringVar(&publicKeyPathArg, "k", publicKeyPathArg, "private key file")
	flag.Parse()

	args = flag.Args()
}

func enc() error {

	return nil
}

func createKey() error {
	homeDirPath, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("load user directory: %w", err)
	}

	keyDir := path.Join(homeDirPath, keyDirName)

	err = initDir(keyDir)
	if err != nil {
		return fmt.Errorf("init directory: %w", err)
	}

	privateKeyPath = path.Join(keyDir, privatekeyName)
	publicKeyPath = path.Join(keyDir, publicKeyName)

	_, err = os.Stat(privateKeyPath)
	if !os.IsNotExist(err) {
		return fmt.Errorf("private key already existed")
	}

	privateKeyData, publicKeyData, err := createNewKey(keySize, keyType)
	if err != nil {
		return fmt.Errorf("create new key: %v", err)
	}

	err = os.WriteFile(privateKeyPath, privateKeyData, 0600)
	if err != nil {
		return fmt.Errorf("create private key file: %v", err)
	}

	err = os.WriteFile(publicKeyPath, publicKeyData, 0600)
	if err != nil {
		return fmt.Errorf("create public key file: %v", err)
	}

	return nil
}

func createNewKey(keySize int, keyType string) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}

	privateKeyData := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyData := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	pemPriBlock := pem.Block{
		Type:  keyType,
		Bytes: privateKeyData,
	}

	pemPubBlock := pem.Block{
		Type:  keyType,
		Bytes: publicKeyData,
	}

	return pem.EncodeToMemory(&pemPriBlock), pem.EncodeToMemory(&pemPubBlock), nil
}
