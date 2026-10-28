package main

import (
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
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
	AESCipherSize int
	AESNonceSize  int
	SHA256        hash.Hash
}

type RaesDecrypter struct {
	Reader               io.Reader
	Writer               io.Writer
	AEAD                 cipher.AEAD
	RsaPrivateKey        *rsa.PrivateKey
	AESCipherSize        int
	AESNonceSize         int
	SHA256               hash.Hash
	OriginHashCiphertext []byte
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

	encFileHeader []byte = []byte("RAESCIPHERTEXT")
	keyType       string = "RAES PRIVATE KEY"
	keyDirName           = ".raes"

	rsaKeyBits           int = 4096
	aesKeySize           int = 256 / 8
	aesKeyCiphertextSize int = rsaKeyBits / 8
	aesNonceSize         int = 12
	aesCipherTextSize    int = 1024 * 32
	hashCiphertextSize   int = 32 + aesNonceSize + aesTagSize
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

	outputPath, err := addSubfixBeforeExt(outputPath)
	if err != nil {
		return fmt.Errorf("add subfix: %w", err)
	}

	rsaPublicKey, err := loadPublicKey()
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer input.Close()

	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer output.Close()

	err = func() error {
		raesEncrypter, err := newRaesEncrypter(input, output, rsaPublicKey)
		if err != nil {
			return fmt.Errorf("create raes encrypter: %w", err)
		}

		err = raesEncrypter.Encrypt()
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		err = raesEncrypter.WriteHash()
		if err != nil {
			return fmt.Errorf("write hash: %w", err)
		}

		return nil
	}()

	if err != nil {
		if err := os.Remove(output.Name()); err != nil {
			return fmt.Errorf("remove damage file: %w", err)
		}
		return err
	}

	return nil
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

	err = func() error {
		raesDecrypter, err := newRaesDecrypter(input, output, rsaPrivateKey)
		if err != nil {
			return fmt.Errorf("create decrypter: %w", err)
		}

		err = raesDecrypter.Decrypte()
		if err != nil {
			return err
		}

		err = raesDecrypter.AuthHash()
		if err != nil {
			return fmt.Errorf("check integrity: %w", err)
		}

		return nil
	}()

	if err != nil {
		if err := os.Remove(output.Name()); err != nil {
			return fmt.Errorf("remove damage file: %w", err)
		}
		return err
	}

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

		err = initDir(path.Dir(publicKeyPath))
		if err != nil {
			return fmt.Errorf("create public directory: %w", err)
		}
		err = os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pemBlock), 0600)
		if err != nil {
			return fmt.Errorf("save public key: %w", err)
		}
	}

	return nil
}