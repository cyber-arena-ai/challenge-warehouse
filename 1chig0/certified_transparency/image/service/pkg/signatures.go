package pkg

import (
	"certified-transparency/pkg/models"
	"crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

func SignHash(key ed25519.PrivateKey, hash models.Hash) []byte {
	return ed25519.Sign(key, hash[:])
}

func VerifyHash(key ed25519.PublicKey, hash models.Hash, signature []byte) bool {
	if key == nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(key, hash[:], signature)
}

func SignOwnership(key ed25519.PrivateKey, ownership *models.SignedOwnershipTimestamp) {
	ownership.Signature = SignHash(key, ownership.Checksum())
}

func VerifyOwnership(key ed25519.PublicKey, ownership *models.SignedOwnershipTimestamp) bool {
	return VerifyHash(key, ownership.Checksum(), ownership.Signature)
}

func SignLeaf(key ed25519.PrivateKey, leaf *models.TreeLeaf) []byte {
	return SignHash(key, sha3.Sum256(leaf.Serialize()))
}

func VerifyLeaf(key ed25519.PublicKey, leaf *models.TreeLeaf, signature []byte) bool {
	return VerifyHash(key, sha3.Sum256(leaf.Serialize()), signature)
}

func SignTreeHead(key ed25519.PrivateKey, sth *models.SignedTreeHead) {
	sth.Signature = SignHash(key, sth.Checksum())
}

func VerifyTreeHead(key ed25519.PublicKey, sth *models.SignedTreeHead) bool {
	return VerifyHash(key, sth.Checksum(), sth.Signature)
}
