package storage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"os"
)

func generateSignKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("data/sign-keys", bytes.Join([][]byte{pubkey, privkey}, []byte{}), 0600)
	if err != nil {
		log.Fatal(err)
	}
	return pubkey, privkey
}

func LoadSignKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	data, err := os.ReadFile("data/sign-keys")
	if err != nil && os.IsNotExist(err) {
		return generateSignKeys()
	}

	return data[:ed25519.PublicKeySize], data[ed25519.PublicKeySize:]
}

func generateClientSignKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("data-client/sign-keys", bytes.Join([][]byte{pubkey, privkey}, []byte{}), 0600)
	if err != nil {
		log.Fatal(err)
	}
	return pubkey, privkey
}

func LoadClientSignKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	data, err := os.ReadFile("data-client/sign-keys")
	if err != nil && os.IsNotExist(err) {
		return generateClientSignKeys()
	}

	return data[:ed25519.PublicKeySize], data[ed25519.PublicKeySize:]
}

func generateEncryptionKey() []byte {
	enckey := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, enckey)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("data/encrypt-key", enckey, 0600)
	if err != nil {
		log.Fatal(err)
	}
	return enckey
}

func LoadEncryptionKey() []byte {
	data, err := os.ReadFile("data/encrypt-key")
	if err != nil && os.IsNotExist(err) {
		return generateEncryptionKey()
	}

	return data
}
