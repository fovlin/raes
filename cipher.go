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

func newRaesEncrypter(writer io.Writer, rsaPublicKey *rsa.PublicKey, aesKey []byte) (RaesEncrypter, error) {
	aesKeyCipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, aesKey, nil)
	if err != nil {
		return RaesEncrypter{}, fmt.Errorf("encrypt aes key: %w", err)
	}

	writer.Write(aesKeyCipherText)

	aesBlock, err := aes.NewCipher(aesKey)
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return RaesEncrypter{}, fmt.Errorf("create aes cipher: %w", err)
	}

	raesEncrypter := RaesEncrypter{
		Writer:       writer,
		AEAD:         aead,
		RsaPublicKey: rsaPublicKey,
		BlockSize:    aesBlockSize,
		NonceSize:    nonceSize,
	}

	return raesEncrypter, nil
}

func createAESCipherBlock(aead cipher.AEAD, plainText []byte) (CipherTextBlock, error) {
	var nonce []byte = make([]byte, nonceSize)
	var nonceSizeData = make([]byte, nonceSizeDataSize)

	_, err := rand.Reader.Read(nonce)
	if err != nil {
		return CipherTextBlock{}, fmt.Errorf("create nonce: %w", err)
	}

	cipherText := aead.Seal(nil, nonce, plainText, nil)

	binary.BigEndian.PutUint32(nonceSizeData, uint32(len(nonce)))

	cipherTextBlock := CipherTextBlock{
		NonceSizeData: nonceSizeData,
		Nonce:         nonce,
		CipherText:    cipherText,
	}

	return cipherTextBlock, nil
}
