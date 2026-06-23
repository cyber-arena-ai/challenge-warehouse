package models

import (
	"crypto/ed25519"
	"time"
)

type Hash = [32]byte

func ToHash(data []byte) Hash {
	h := Hash{}
	copy(h[:], data)
	return h
}

type Ownership struct {
	ContentHash Hash
	Name        string
}

type SignedOwnershipTimestamp struct {
	Timestamp time.Time
	Ownership Ownership
	Signature []byte
}

type SignedTreeHead struct {
	Size      uint64
	Timestamp time.Time
	Hash      Hash
	Signature []byte
}

type TreeLeaf struct {
	Created              time.Time
	Ownership            Ownership
	PubKey               ed25519.PublicKey
	DataForPrivateClaims []byte // encrypted contact information
	DataForPublicClaims  []byte // encrypted contact information
}

type TreeLeafProof struct {
	Head   SignedTreeHead
	Index  uint64
	Leaf   TreeLeaf
	Hashes []Hash
}
