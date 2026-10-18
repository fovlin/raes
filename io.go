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
	var cipherDataBlock []byte
	var blockSizeData = make([]byte, aesBlockSizeDataSize)

	cipherBlock, err := createAESCipherBlock(encrypter.AEAD, plainText)
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}

	cipherDataBlock = append(cipherDataBlock, cipherBlock.Nonce...)
	cipherDataBlock = append(cipherDataBlock, cipherBlock.CipherText...)

	blockSize := uint32(len(cipherDataBlock))
	binary.BigEndian.PutUint32(blockSizeData, blockSize)

	return encrypter.Writer.Write(cipherDataBlock)
}

func (encrypter RaesEncrypter) Encrypt() error {
	var plainText []byte = make([]byte, encrypter.AESCipherSize)

	for {
		readSize, err := io.ReadFull(encrypter.Reader, plainText)
		if err == io.EOF {
			break
		}

		if err != io.ErrUnexpectedEOF && err != nil {
			return fmt.Errorf("read plaintext data: %w", err)
		}

		_, err = encrypter.Write(plainText[:readSize])
		if err != nil {
			return fmt.Errorf("write cipher block: %w", err)
		}
	}
	return nil
}

func (decrypter RaesDecrypter) Read() ([]byte, error) {
	var nonce = make([]byte, aesNonceSize)
	var ciphertext = make([]byte, aesCipherTextSize + aesTagSize)

	readedNonceSize, err := io.ReadFull(decrypter.Reader, nonce)
	if err == io.EOF {
		return nil, err
	}

	if err != io.ErrUnexpectedEOF && err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	readedCipherSize, err := io.ReadFull(decrypter.Reader, ciphertext)
	if err == io.EOF {
		return nil, err
	}

	if err != io.ErrUnexpectedEOF && err != nil {
		return nil, fmt.Errorf("read ciphertext: %w", err)
	}

	plaintext, err := decrypter.AEAD.Open(nil, nonce[:readedNonceSize], ciphertext[:readedCipherSize], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}
func (decrypter RaesDecrypter) Decrypte() error {
	for {
		plaintext, err := decrypter.Read()
		if err == io.EOF {
			break
		}

		if err != io.ErrUnexpectedEOF && err != nil {
			return fmt.Errorf("read plaintext: %w", err)
		}

		_, err = decrypter.Writer.Write(plaintext)
		if err != nil{
			return err
		}
	}

	return nil
}
