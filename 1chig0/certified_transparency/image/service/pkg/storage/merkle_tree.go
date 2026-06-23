package storage

import (
	"bytes"
	"certified-transparency/pkg/models"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	"sync"
	"time"
)

func HashLeaf(leaf models.TreeLeaf) models.Hash {
	return sha3.Sum256(leaf.Serialize())
}

func HashIntermediate(left models.Hash, right models.Hash) models.Hash {
	return sha3.Sum256(bytes.Join([][]byte{left[:], right[:]}, []byte{}))
}

type TreeIntermediatePos struct {
	Left  uint64
	Right uint64
}

func (pos TreeIntermediatePos) IsRoot(size uint64) bool {
	return pos.Left == 0 && pos.Right >= size
}

func (pos TreeIntermediatePos) IsLeftChild() bool {
	return pos.Left&(pos.Right-pos.Left) == 0
}

func (pos TreeIntermediatePos) Parent() TreeIntermediatePos {
	if pos.IsLeftChild() {
		return TreeIntermediatePos{
			Left:  pos.Left,
			Right: pos.Right + pos.Right - pos.Left,
		}
	} else {
		return TreeIntermediatePos{
			Left:  pos.Left - (pos.Right - pos.Left),
			Right: pos.Right,
		}
	}
}

func (pos TreeIntermediatePos) Sibling() TreeIntermediatePos {
	if pos.IsLeftChild() {
		return TreeIntermediatePos{Left: pos.Right, Right: pos.Right + (pos.Right - pos.Left)}
	} else {
		return TreeIntermediatePos{Left: pos.Left - (pos.Right - pos.Left), Right: pos.Left}
	}
}

type MerkleTree struct {
	mu   sync.Mutex
	repo Repository
	size uint64
}

func NewMerkleTree(repo Repository) *MerkleTree {
	tx := repo.ReadTransaction()
	defer tx.Discard()
	size, err := tx.GetSize()
	if err != nil {
		log.Fatal(err)
	}

	return &MerkleTree{
		repo: repo,
		size: size,
	}
}

func (t *MerkleTree) Size() uint64 {
	return t.size
}

// Head result is not yet signed!
func (t *MerkleTree) Head() models.SignedTreeHead {
	tx := t.repo.ReadTransaction()
	defer tx.Discard()
	return models.SignedTreeHead{
		Size:      t.size,
		Timestamp: time.Now(),
		Hash:      t.getHash(tx, t.rootPos()),
	}
}

func (t *MerkleTree) GetLeaf(index uint64) (*models.TreeLeaf, error) {
	tx := t.repo.ReadTransaction()
	defer tx.Discard()
	return tx.GetLeaf(index)
}

func (t *MerkleTree) Append(leaf models.TreeLeaf) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tx := t.repo.WriteTransaction()
	defer tx.Discard()

	index := t.size

	err := tx.PutLeaf(index, leaf)
	if err != nil {
		return 0, err
	}
	err = t.updateHashes(tx, index, HashLeaf(leaf))
	if err != nil {
		return 0, err
	}
	t.size += 1
	err = tx.PutSize(t.size)
	if err != nil {
		return 0, err
	}

	err = tx.Commit()

	return index, err
}

func (t *MerkleTree) rootPos() TreeIntermediatePos {
	pos := TreeIntermediatePos{
		Left:  0,
		Right: 1,
	}
	for pos.Right < t.size {
		pos.Right *= 2
	}
	return pos
}

func (t *MerkleTree) getHash(tx Transaction, pos TreeIntermediatePos) models.Hash {
	if pos.Right-pos.Left == 1 {
		// leaf
		node, err := tx.GetLeaf(pos.Left)
		if node == nil || err != nil {
			return models.Hash{}
		}
		return HashLeaf(*node)
	}
	// intermediate/root node
	hash, err := tx.GetIntermediateHash(pos)
	if hash == nil || err != nil {
		return models.Hash{}
	}
	return *hash
}

func (t *MerkleTree) updateHashes(tx Transaction, index uint64, hash models.Hash) error {
	pos := TreeIntermediatePos{index, index + 1}
	for !pos.IsRoot(t.size) {
		parent := pos.Parent()
		hash2 := t.getHash(tx, pos.Sibling())
		if pos.IsLeftChild() {
			hash = HashIntermediate(hash, hash2)
		} else {
			hash = HashIntermediate(hash2, hash)
		}
		err := tx.PutIntermediateHash(parent, hash)
		if err != nil {
			return err
		}
		pos = parent
	}
	return nil
}

func (t *MerkleTree) GetLeafProof(index uint64) (models.TreeLeafProof, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tx := t.repo.ReadTransaction()
	defer tx.Discard()

	proof := models.TreeLeafProof{
		Head:   t.Head(),
		Index:  index,
		Hashes: make([]models.Hash, 0),
	}

	leaf, err := tx.GetLeaf(index)
	if err != nil {
		return proof, err
	}
	if leaf == nil {
		return proof, fmt.Errorf("index %d does not exist", index)
	}
	proof.Leaf = *leaf

	pos := TreeIntermediatePos{index, index + 1}
	for !pos.IsRoot(t.size) {
		proof.Hashes = append(proof.Hashes, t.getHash(tx, pos.Sibling()))
		pos = pos.Parent()
	}

	return proof, nil
}

// VerifyLeafProofHashes checks hash chain against sth, but not sth signature
func VerifyLeafProofHashes(proof models.TreeLeafProof) bool {
	hash := HashLeaf(proof.Leaf)
	pos := TreeIntermediatePos{Left: proof.Index, Right: proof.Index + 1}
	for _, hash2 := range proof.Hashes {
		if pos.IsRoot(proof.Head.Size) {
			return false
		}
		if pos.IsLeftChild() {
			hash = HashIntermediate(hash, hash2)
		} else {
			hash = HashIntermediate(hash2, hash)
		}
		pos = pos.Parent()
	}

	return pos.IsRoot(proof.Index) && bytes.Equal(hash[:], proof.Head.Hash[:])
}
