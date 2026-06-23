package storage

import (
	"bytes"
	"certified-transparency/pkg/models"
	"encoding/binary"
	"errors"
	"github.com/dgraph-io/badger/v4"
)

func serializeUInt(i uint64) []byte {
	buf := bytes.Buffer{}
	_ = binary.Write(&buf, binary.BigEndian, i)
	return buf.Bytes()
}

func unserializeUInt(data []byte) uint64 {
	buf := bytes.NewBuffer(data)
	var i uint64
	_ = binary.Read(buf, binary.BigEndian, &i)
	return i
}

func serializeUIntPair(a uint64, b uint64) []byte {
	buf := bytes.Buffer{}
	_ = binary.Write(&buf, binary.BigEndian, a)
	_ = binary.Write(&buf, binary.BigEndian, b)
	return buf.Bytes()
}

var sizeKey = []byte("size")

type Repository struct {
	db *badger.DB
}

func (repo Repository) ReadTransaction() Transaction {
	return Transaction{repo.db.NewTransaction(false)}
}

func (repo Repository) WriteTransaction() Transaction {
	return Transaction{repo.db.NewTransaction(true)}
}

func (repo Repository) Close() {
	_ = repo.db.Close()
}

type Transaction struct {
	tx *badger.Txn
}

func (tx Transaction) Discard() {
	tx.tx.Discard()
}

func (tx Transaction) Commit() error {
	return tx.tx.Commit()
}

func (tx Transaction) PutLeaf(key uint64, value models.TreeLeaf) error {
	return tx.tx.Set(serializeUInt(key), value.Serialize())
}

func (tx Transaction) GetLeaf(key uint64) (*models.TreeLeaf, error) {
	item, err := tx.tx.Get(serializeUInt(key))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	serialized, err := item.ValueCopy(make([]byte, 0))
	if err != nil {
		return nil, err
	}
	leaf, err := models.UnserializeTreeLeaf(serialized)
	return &leaf, err
}

func (tx Transaction) PutIntermediateHash(key TreeIntermediatePos, value models.Hash) error {
	return tx.tx.Set(serializeUIntPair(key.Left, key.Right), value[:])
}

func (tx Transaction) GetIntermediateHash(key TreeIntermediatePos) (*models.Hash, error) {
	item, err := tx.tx.Get(serializeUIntPair(key.Left, key.Right))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	serialized, err := item.ValueCopy(make([]byte, 0))
	if err != nil {
		return nil, err
	}
	return (*models.Hash)(serialized), err
}

func (tx Transaction) PutSize(size uint64) error {
	return tx.tx.Set(sizeKey, serializeUInt(size))
}

func (tx Transaction) GetSize() (uint64, error) {
	item, err := tx.tx.Get(sizeKey)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return 0, nil // empty database
	}
	if err != nil {
		return 0, err
	}
	serialized, err := item.ValueCopy(make([]byte, 0))
	if err != nil {
		return 0, err
	}
	return unserializeUInt(serialized), nil
}
