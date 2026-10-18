package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
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

	writer.Write(append(aesKeyCipherText, make([]byte, hashSize)...))

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
		SHA256:        sha256.New(),
	}

	return raesEncrypter, nil
}

func newRaesDecrypter(reader io.Reader, writer io.Writer, rsaPrivateKey *rsa.PrivateKey) (RaesDecrypter, error) {
	header := make([]byte, aesKeyCipherSize + hashSize)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return RaesDecrypter{}, fmt.Errorf("load aes key from file header: %w", err)
	}

	aesKeyCipher := header[:512]
	originHash := header[512:]

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
		SHA256:        sha256.New(),
		OriginHash:    originHash,
	}

	return raesDecrypter, nil
}

func createAESCipherBlock(aead cipher.AEAD, plainText []byte) (CipherTextBlock, error) {
	var nonce []byte = make([]byte, aesNonceSize)

	_, err := rand.Reader.Read(nonce)
	if err != nil {
		return CipherTextBlock{}, fmt.Errorf("create nonce: %w", err)
	}

	cipherText := aead.Seal(nil, nonce, plainText, nil)

	cipherTextBlock := CipherTextBlock{
		Nonce:      nonce,
		CipherText: cipherText,
	}

	return cipherTextBlock, nil
}


func (encrypter RaesEncrypter) Write(plainText []byte) (int, error) {
	var cipherDataBlock []byte

	cipherBlock, err := createAESCipherBlock(encrypter.AEAD, plainText)
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}

	cipherDataBlock = append(cipherDataBlock, cipherBlock.Nonce...)
	cipherDataBlock = append(cipherDataBlock, cipherBlock.CipherText...)

	return encrypter.Writer.Write(cipherDataBlock)
}

func (encrypter RaesEncrypter) Encrypt() error {
	var plaintext []byte = make([]byte, encrypter.AESCipherSize)

	for {
		readSize, err := io.ReadFull(encrypter.Reader, plaintext)
		if err == io.EOF {
			break
		}

		if err != io.ErrUnexpectedEOF && err != nil {
			return fmt.Errorf("read plaintext data: %w", err)
		}

		_, err = encrypter.Write(plaintext[:readSize])
		if err != nil {
			return fmt.Errorf("write cipher block: %w", err)
		}

		_, err = encrypter.SHA256.Write(plaintext[:readSize])
		if err != nil {
			return fmt.Errorf("hash writer: %w", err)
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

		_, err = decrypter.SHA256.Write(plaintext)
		if err != nil {
			return fmt.Errorf("hash writer: %w", err)
		}
	}

	return nil
}

func writeHash(file *os.File, hashData hash.Hash) error {
	_, err := file.Seek(int64(rsaKeySize / 8), 0)
	if err != nil {
		return fmt.Errorf("auth hash: %w", err)
	}
	file.Write(hashData.Sum(nil))
	return nil
}


func authHash(hashData hash.Hash, originHash []byte) error {
	if hex.EncodeToString(originHash) != hex.EncodeToString(hashData.Sum(nil)) {
		return fmt.Errorf("auth hash: integrity check error, the file may have been altered")
	}

	return nil
}