package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
)

func newRaesEncrypter(rsaPublicKey *rsa.PublicKey, aesKey []byte) RaesEncrypter {
	return RaesEncrypter{
		AesKey:       aesKey,
		RsaPublicKey: rsaPublicKey,
		BlockSize:    1024 * 32,
		NonceSize:    14,
	}
}

func blockCrypt(aead cipher.AEAD, plainText []byte) (CipherTextBlock, error) {
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
