package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

func newRaesEncrypter(reader io.Reader, writer io.Writer, rsaPublicKey *rsa.PublicKey) (RaesEncrypter, error) {
	aesKey := make([]byte, aesKeySize)
	_, err := rand.Reader.Read(aesKey)
	if err != nil {
		return RaesEncrypter{}, fmt.Errorf("create aes key: %w", err)
	}

	aesKeyCipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, aesKey, nil)
	if err != nil {
		return RaesEncrypter{}, fmt.Errorf("encrypt aes key: %w", err)
	}

	writer.Write(aesKeyCipherText)

	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return RaesEncrypter{}, fmt.Errorf("create aes block: %w", err)
	}

	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return RaesEncrypter{}, fmt.Errorf("create aead: %w", err)
	}

	raesEncrypter := RaesEncrypter{
		Reader:        reader,
		Writer:        writer,
		AEAD:          aead,
		RsaPublicKey:  rsaPublicKey,
		AESCipherSize: aesCipherTextSize,
		AESNonceSize:  aesNonceSize,
	}

	return raesEncrypter, nil
}

func newRaesDecrypter(reader io.Reader, writer io.Writer, rsaPrivateKey *rsa.PrivateKey) (RaesDecrypter, error) {
	aesKeyCipher := make([]byte, aesKeyCipherSize)
	_, err := io.ReadFull(reader, aesKeyCipher)
	if err != nil {
		return RaesDecrypter{}, fmt.Errorf("load aes key from file header: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, aesKeyCipher, nil)
	if err != nil {
		return RaesDecrypter{}, fmt.Errorf("decrypt aes key: %w", err)
	}

	aesBlock, err := aes.NewCipher(aesKey)
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return RaesDecrypter{}, fmt.Errorf("create aead: %w", err)
	}

	raesDecrypter := RaesDecrypter{
		Reader:        reader,
		Writer:        writer,
		AEAD:          aead,
		RsaPrivateKey: rsaPrivateKey,
		AESCipherSize: aesCipherTextSize,
		AESNonceSize:  aesNonceSize,
	}

	return raesDecrypter, nil
}

func createAESCipherBlock(aead cipher.AEAD, plainText []byte) (CipherTextBlock, error) {
	var nonce []byte = make([]byte, aesNonceSize)
	var nonceSizeData = make([]byte, aesNonceSizeDataSize)

	_, err := rand.Reader.Read(nonce)
	if err != nil {
		return CipherTextBlock{}, fmt.Errorf("create nonce: %w", err)
	}

	cipherText := aead.Seal(nil, nonce, plainText, nil)

	binary.BigEndian.PutUint32(nonceSizeData, uint32(len(nonce)))

	cipherTextBlock := CipherTextBlock{
		Nonce:      nonce,
		CipherText: cipherText,
	}

	return cipherTextBlock, nil
}
