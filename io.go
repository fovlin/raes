package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
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