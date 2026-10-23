package gm

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/tjfoc/gmsm/sm4"
)

// PKCS7Padding 填充
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding 去除填充
func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, errors.New("sm4: empty decrypted data")
	}
	unpadding := int(origData[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, errors.New("sm4: invalid padding")
	}
	return origData[:(length - unpadding)], nil
}

// SM4EncryptCBC 使用国密 SM4 CBC 模式加密数据（密钥必须为 16 字节）
func SM4EncryptCBC(key []byte, plainText []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("sm4: key size must be 16 bytes, got %d", len(key))
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := PKCS7Padding(plainText, block.BlockSize())
	cipherText := make([]byte, block.BlockSize()+len(padded))
	iv := cipherText[:block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[block.BlockSize():], padded)

	return cipherText, nil
}

// SM4DecryptCBC 使用国密 SM4 CBC 模式解密数据
func SM4DecryptCBC(key []byte, cipherText []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("sm4: key size must be 16 bytes, got %d", len(key))
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(cipherText) < blockSize*2 || len(cipherText)%blockSize != 0 {
		return nil, errors.New("sm4: ciphertext size is invalid")
	}

	iv := cipherText[:blockSize]
	rawCipher := cipherText[blockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	plainPadded := make([]byte, len(rawCipher))
	mode.CryptBlocks(plainPadded, rawCipher)

	return PKCS7UnPadding(plainPadded)
}
