package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"
)

type RaesEncrypter struct {
	AesKey       []byte
	RsaPublicKey *rsa.PublicKey
	BlockSize    int
	NonceSize    int
}

type CipherTextBlock struct {
	Size uint32
	Nonce []byte
	Data []byte
}

var (
	cmdMap = map[string]func() error{
		"gen-key": genKey,
		"enc":     enc,
	}

	args              []string
	subCmdArgs        []string
	privateKeyPath    string
	publicKeyPath     string
	privateKeyPathArg string
	publicKeyPathArg  string
	privatekeyName    string = "raes_key"
	publicKeyName     string = "raes_key.pub"
	keySize           int    = 4096
	keyType           string = "PRIVATE KEY"
	keyDirName               = ".raes"
)

func main() {
	err := initProgram()
	if err != nil {
		log.Fatalln(err)
	}

	if len(args) < 1 {
		log.Fatalln("command missing")
	}

	cmd := args[0]

	function, ok := cmdMap[cmd]
	if !ok {
		log.Fatalln("unknown command:", cmd)
	}

	err = function()
	if err != nil {
		log.Fatalln(err)
	}
}

func enc() error {
	if len(subCmdArgs) < 1 {
		return fmt.Errorf("usage: raes enc <input> [output]")
	}

	var inputPath string = subCmdArgs[0]
	var outputPath string = inputPath + ".enc"

	if len(subCmdArgs) > 1 {
		outputPath = subCmdArgs[1]
	}

	rsaPublicKey, err := loadPublicKey()
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	aesKey := make([]byte, 32)
	_, err = rand.Reader.Read(aesKey)
	if err != nil {
		return fmt.Errorf("create aes key: %w", err)
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}

	output, err := os.Open(outputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}

	raesEncrypter := newRaesEncrypter(rsaPublicKey, aesKey)
	raesEncrypter.Encrypt(input, output)

	defer input.Close()
	defer output.Close()

	return nil
}

func genKey() error {
	_, err := os.Stat(privateKeyPath)
	switch true {
	case os.IsNotExist(err):
		err := createAngSaveKey()
		if err != nil {
			return fmt.Errorf("create key: %w", err)
		}

	case !os.IsNotExist(err):
		privateKey, err := loadPrivateKey()
		if err != nil {
			return fmt.Errorf("load private key: %w", err)
		}

		pemBlock := pem.Block{
			Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
			Type:  keyType,
		}

		initDir(path.Dir(publicKeyPath))
		os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pemBlock), 0600)
	}

	return nil
}

func createKey(keySize int, keyType string) ([]byte, []byte, error) {
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
