package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

const (
	DATA_FOR_PRIVATE_CLAIM = "\x00\x01"
	DATA_FOR_PUBLIC_CLAIM  = "\x00\x02"
)

func Encrypt(key []byte, data []byte, what string) []byte {

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	return gcm.Seal(nonce, nonce, data, []byte(what))
}

func Decrypt(key []byte, data []byte, what string) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	if len(data) <= gcm.NonceSize() {
		return nil
	}

	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(what))
	if err != nil {
		return nil
	}

	return plain
}
