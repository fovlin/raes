package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	_, err = writer.Write(bytes.Join([][]byte{encFileHeader, aesKeyCipherText, make([]byte, hashCiphertextSize)}, nil))
	if err != nil {
		return RaesEncrypter{}, fmt.Errorf("write header: %w", err)
	}

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
	header := make([]byte, len(encFileHeader)+aesKeyCiphertextSize+hashCiphertextSize)
	readedHeaderSize, err := io.ReadFull(reader, header)
	if err != nil {
		fmt.Println(readedHeaderSize)
		return RaesDecrypter{}, fmt.Errorf("load file header: %w", err)
	}

	if readedHeaderSize < len(encFileHeader)+aesKeyCiphertextSize+hashCiphertextSize || hex.EncodeToString(header[:len(encFileHeader)]) != hex.EncodeToString(encFileHeader) {
		return RaesDecrypter{}, fmt.Errorf("check header: not a ciphertext file")
	}

	aesKeyCiphertext := header[len(encFileHeader):len(encFileHeader)+aesKeyCiphertextSize]
	originHashCiphertext := header[len(encFileHeader)+aesKeyCiphertextSize:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, aesKeyCiphertext, nil)
	if err != nil {
		return RaesDecrypter{}, fmt.Errorf("decrypt aes key: %w", err)
	}

	aesBlock, err := aes.NewCipher(aesKey)
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return RaesDecrypter{}, fmt.Errorf("create aead: %w", err)
	}

	raesDecrypter := RaesDecrypter{
		Reader:               reader,
		Writer:               writer,
		AEAD:                 aead,
		RsaPrivateKey:        rsaPrivateKey,
		AESCipherSize:        aesCipherTextSize,
		AESNonceSize:         aesNonceSize,
		SHA256:               sha256.New(),
		OriginHashCiphertext: originHashCiphertext,
	}

	return raesDecrypter, nil
}

func (encrypter RaesEncrypter) AEADBlockEncrypt(plainText []byte) ([]byte, error) {
	var nonce []byte = make([]byte, aesNonceSize)

	_, err := rand.Reader.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("create nonce: %w", err)
	}

	cipherText := encrypter.AEAD.Seal(nil, nonce, plainText, nil)

	return append(nonce, cipherText...), nil
}

func (encrypter RaesEncrypter) Write(plainText []byte) (int, error) {
	ciphertextBlock, err := encrypter.AEADBlockEncrypt(plainText)
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}

	return encrypter.Writer.Write(ciphertextBlock)
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
	var ciphertextBlock = make([]byte, aesNonceSize+aesCipherTextSize+aesTagSize)

	readedCipherSize, err := io.ReadFull(decrypter.Reader, ciphertextBlock)
	if err == io.EOF {
		return nil, err
	}

	if err != io.ErrUnexpectedEOF && err != nil {
		return nil, err
	}

	if readedCipherSize < aesNonceSize {
		return nil, fmt.Errorf("damaged ciphertext block")
	}

	plaintext, err := decrypter.AEAD.Open(nil, ciphertextBlock[:aesNonceSize], ciphertextBlock[aesNonceSize:readedCipherSize], nil)
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
		if err != nil {
			return err
		}

		_, err = decrypter.SHA256.Write(plaintext)
		if err != nil {
			return fmt.Errorf("hash writer: %w", err)
		}
	}

	return nil
}

func (encrypter RaesEncrypter) WriteHash() error {
	file, ok := encrypter.Writer.(*os.File)
	if !ok {
		return fmt.Errorf("object not a file")
	}

	hashCipher, err := encrypter.AEADBlockEncrypt(encrypter.SHA256.Sum(nil))
	if err != nil {
		return fmt.Errorf("encrypt hash: %w", err)
	}

	_, err = file.Seek(int64(len(encFileHeader)+aesKeyCiphertextSize), 0)
	if err != nil {
		return err
	}
	_, err = file.Write(hashCipher)
	if err != nil {
		return err
	}
	return nil
}

func (decrypter RaesDecrypter) AuthHash() error {
	originHash, err := decrypter.AEAD.Open(nil, decrypter.OriginHashCiphertext[:aesNonceSize], decrypter.OriginHashCiphertext[aesNonceSize:], nil)
	if err != nil {
		return err
	}

	if hex.EncodeToString(originHash) != hex.EncodeToString(decrypter.SHA256.Sum(nil)) {
		return fmt.Errorf("auth hash: integrity check error, the file may have been altered")
	}

	return nil
}
