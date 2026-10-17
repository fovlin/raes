package main

import (
	"crypto/rsa"
)

func newRaesEncrypter(rsaPublicKey *rsa.PublicKey, aesKey []byte, ) RaesEncrypter {
	return RaesEncrypter{
		AesKey: aesKey,
		RsaPublicKey: rsaPublicKey,
		BlockSize: 1024 * 32,
		NonceSize: 14,
	}
}