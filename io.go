package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

func loadPublicKey() (*rsa.PublicKey, error) {
	if len(publicKeyPathArg) == 0 {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("load home dirctory: %w", err)
		}
		publicKeyPath = path.Join(homeDir, keyDirName, publicKeyName)
	}

	if len(publicKeyPathArg) != 0 {
		publicKeyPath = publicKeyPathArg
	}

	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}

	pemBlock, _ := pem.Decode(publicKeyData)

	key, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key data: %w", err)
	}

	return key, nil
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	if len(privateKeyPathArg) == 0 {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("load home dirctory: %w", err)
		}
		privateKeyPath = path.Join(homeDir, keyDirName, privatekeyName)
	}

	if len(privateKeyPathArg) != 0 {
		privateKeyPath = privateKeyPathArg
	}

	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}

	pemBlock, _ := pem.Decode(privateKeyData)

	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key data: %w", err)
	}

	return key, nil
}

func createAngSaveKey() error {
	privateKeyData, publicKeyData, err := createKey(rsaKeySize, keyType)
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

func addSubfixBeforeExt(outputPath string) (string, error) {
	resultPath := outputPath

	for number := 1; number > 0; number++ {
		_, err := os.Stat(resultPath)

		switch true {
		case os.IsNotExist(err):
			return resultPath, nil

		case err != nil:
			return "", err
		}

		resultPath = outputPath

		dir := path.Dir(resultPath)
		basePath := path.Base(resultPath)
		ext := path.Ext(basePath)
		pureName, _ := strings.CutSuffix(basePath, ext)
		pureName += fmt.Sprint("-", number)

		resultPath = path.Join(dir, fmt.Sprint(pureName, ext))
	}

	return resultPath, nil
}

func (encrypter RaesEncrypter) Write(plainText []byte) (int, error) {
	var blockData []byte
	var blockSizeData = make([]byte, blockSizeDataSize)

	cipherBlock, err := createAESCipherBlock(encrypter.AEAD, plainText)
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}

	blockData = append(blockData, cipherBlock.NonceSizeData...)
	blockData = append(blockData, cipherBlock.Nonce...)
	blockData = append(blockData, cipherBlock.CipherText...)

	blockSize := uint32(len(blockData))
	binary.BigEndian.PutUint32(blockSizeData, blockSize)

	fmt.Println(blockSize)
	_, err = encrypter.Writer.Write(blockSizeData)
	if err != nil {
		return 0, fmt.Errorf("write block size data: %w", err)
	}

	return encrypter.Writer.Write(blockData)
}

func (encrypter RaesEncrypter) Encrypt(input io.Reader) error {
	var plainText []byte = make([]byte, encrypter.BlockSize)

	for {
		readSize, err := input.Read(plainText)
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("read plaintext data: %w", err)
		}

		_, err = encrypter.Write(plainText[:readSize])
		if err != nil {
			return fmt.Errorf("write cipher block: %w", err)
		}
	}
	return nil
}
