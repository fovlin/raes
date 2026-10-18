package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
)

type RaesEncrypter struct {
	Reader        io.Reader
	Writer        io.Writer
	AEAD          cipher.AEAD
	RsaPublicKey  *rsa.PublicKey
	AESCipherSize uint32
	AESNonceSize  uint32
}

type RaesDecrypter struct {
	Reader        io.Reader
	Writer        io.Writer
	AEAD          cipher.AEAD
	RsaPrivateKey *rsa.PrivateKey
	AESCipherSize uint32
	AESNonceSize  uint32
}

type CipherTextBlock struct {
	Nonce      []byte
	CipherText []byte
}

var (
	cmdMap = map[string]func() error{
		"gen-key": genKey,
		"enc":     enc,
		"dec":     dec,
	}

	args       []string
	subCmdArgs []string

	privateKeyPathArg string
	publicKeyPathArg  string

	privatekeyName string = "raes_key"
	publicKeyName  string = "raes_key.pub"
	privateKeyPath string
	publicKeyPath  string

	keyType    string = "PRIVATE KEY"
	keyDirName        = ".raes"

	rsaKeySize       int = 4096
	aesKeySize       int = 256 / 8
	aesKeyCipherSize int = rsaKeySize / 8

	aesNonceSize      uint32 = 12
	aesCipherTextSize uint32 = 1024 * 32

	aesNonceSizeDataSize uint32 = 4
	aesBlockSizeDataSize uint32 = 4
)

const aesTagSize = 16

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

	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}

	outputPath, err = addSubfixBeforeExt(outputPath)
	if err != nil {
		return fmt.Errorf("add subfix: %w", err)
	}

	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}

	raesEncrypter, err := newRaesEncrypter(input, output, rsaPublicKey)
	if err != nil {
		return fmt.Errorf("create raes encrypter: %w", err)
	}

	err = raesEncrypter.Encrypt()
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

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
		fmt.Println("private key exists, will regenerate public key")
		privateKey, err := loadPrivateKey()
		if err != nil {
			return fmt.Errorf("load private key: %w", err)
		}

		pemBlock := pem.Block{
			Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
			Type:  keyType,
		}

		initDir(path.Dir(publicKeyPath))
		err = os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pemBlock), 0600)
		if err != nil {
			return fmt.Errorf("save public key: %w", err)
		}
		
		fmt.Println("regenerated public key:", publicKeyPath)
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

func dec() error {
	if len(subCmdArgs) < 1 {
		return fmt.Errorf("usage: raes enc <input> [output]")
	}

	var inputPath string = subCmdArgs[0]
	outputPath, _ := strings.CutSuffix(inputPath, ".enc")

	if len(subCmdArgs) > 1 {
		outputPath = subCmdArgs[1]
	}

	rsaPrivateKey, err := loadPrivateKey()
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}

	outputPath, err = addSubfixBeforeExt(outputPath)
	if err != nil {
		return fmt.Errorf("add subfix: %w", err)
	}

	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}

	raesDecrypter, err := newRaesDecrypter(input, output, rsaPrivateKey)
	if err != nil {
		return fmt.Errorf("create decrypter: %w", err)
	}

	err = raesDecrypter.Decrypte()
	if err != nil {
		return err
	}
	return nil
}
