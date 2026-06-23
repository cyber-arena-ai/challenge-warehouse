package models

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"golang.org/x/crypto/sha3"
)

const (
	SignatureSize = ed25519.SignatureSize
)

func serializeString(s string) []byte {
	result := []byte(s)
	return append([]byte{byte(len(result))}, result...)
}

func unserializeString(bytes []byte) string {
	return string(bytes[1 : 1+bytes[0]])
}

func writeByteSlice(buf *bytes.Buffer, bytes []byte) {
	_ = binary.Write(buf, binary.BigEndian, uint16(len(bytes)))
	buf.Write(bytes)
}

func readByteSlice(buf *bytes.Buffer) []byte {
	var l uint16
	_ = binary.Read(buf, binary.BigEndian, &l)
	return buf.Next(int(l))
}

func writeHashSlice(buf *bytes.Buffer, hashes []Hash) {
	_ = binary.Write(buf, binary.BigEndian, uint16(len(hashes)))
	for _, hash := range hashes {
		buf.Write(hash[:])
	}
}

func readHashSlice(buf *bytes.Buffer) []Hash {
	var l uint16
	_ = binary.Read(buf, binary.BigEndian, &l)
	result := make([]Hash, 0)
	for i := 0; i < int(l); i++ {
		result = append(result, ToHash(buf.Next(32)))
	}
	return result
}

func (self *Ownership) Serialize() []byte {
	return append(self.ContentHash[:], serializeString(self.Name)...)
}

func UnserializeOwnership(data []byte) Ownership {
	return Ownership{
		ContentHash: ToHash(data[0:32]),
		Name:        unserializeString(data[32:]),
	}
}

func (self *SignedOwnershipTimestamp) Serialize() []byte {
	result, _ := self.Timestamp.MarshalBinary()
	result = append(result, self.Ownership.Serialize()...)
	result = append(result, self.Signature...)
	return result
}

func (self *SignedOwnershipTimestamp) Checksum() Hash {
	ts, _ := self.Timestamp.MarshalBinary()
	return sha3.Sum256(bytes.Join([][]byte{
		[]byte("ownership"),
		ts,
		self.Ownership.Serialize(),
	}, []byte{}))
}

func UnserializeSignedOwnershipTimestamp(data []byte) (SignedOwnershipTimestamp, error) {
	sot := SignedOwnershipTimestamp{
		Ownership: UnserializeOwnership(data[15 : len(data)-SignatureSize]),
		Signature: data[len(data)-SignatureSize:],
	}
	err := sot.Timestamp.UnmarshalBinary(data[:15])
	if err != nil {
		return SignedOwnershipTimestamp{}, err
	}
	return sot, nil
}

func (self *SignedTreeHead) Serialize() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, self.Size)
	ts, _ := self.Timestamp.MarshalBinary()
	buf.Write(ts)
	buf.Write(self.Hash[:])
	buf.Write(self.Signature)
	return buf.Bytes()
}

func (self *SignedTreeHead) Checksum() Hash {
	hash := sha3.New256()
	hash.Write([]byte("sth"))
	_ = binary.Write(hash, binary.BigEndian, self.Size)
	ts, _ := self.Timestamp.MarshalBinary()
	hash.Write(ts)
	return ToHash(hash.Sum(self.Hash[:]))
}

func UnserializeSignedTreeHead(data []byte) (SignedTreeHead, error) {
	buf := bytes.NewBuffer(data)
	result := SignedTreeHead{}
	err := binary.Read(buf, binary.BigEndian, &result.Size)
	if err != nil {
		return result, err
	}
	err = result.Timestamp.UnmarshalBinary(buf.Next(15))
	if err != nil {
		return result, err
	}
	_, _ = buf.Read(result.Hash[:])
	result.Signature = buf.Bytes()
	return result, nil
}

func (self *TreeLeaf) Serialize() []byte {
	buf := new(bytes.Buffer)
	ts, _ := self.Created.MarshalBinary()
	buf.Write(ts)
	writeByteSlice(buf, self.Ownership.Serialize())
	writeByteSlice(buf, self.PubKey)
	writeByteSlice(buf, self.DataForPrivateClaims)
	writeByteSlice(buf, self.DataForPublicClaims)
	return buf.Bytes()
}

func UnserializeTreeLeaf(data []byte) (TreeLeaf, error) {
	buf := bytes.NewBuffer(data)
	result := TreeLeaf{}
	err := result.Created.UnmarshalBinary(buf.Next(15))
	if err != nil {
		return result, err
	}
	result.Ownership = UnserializeOwnership(readByteSlice(buf))
	result.PubKey = readByteSlice(buf)
	result.DataForPrivateClaims = readByteSlice(buf)
	result.DataForPublicClaims = readByteSlice(buf)
	return result, err
}

func (self *TreeLeafProof) Serialize() []byte {
	buf := new(bytes.Buffer)
	writeByteSlice(buf, self.Head.Serialize())
	_ = binary.Write(buf, binary.BigEndian, self.Index)
	writeByteSlice(buf, self.Leaf.Serialize())
	writeHashSlice(buf, self.Hashes)
	return buf.Bytes()
}

func UnserializeTreeLeafProof(data []byte) (TreeLeafProof, error) {
	buf := bytes.NewBuffer(data)
	result := TreeLeafProof{}
	var err error

	result.Head, err = UnserializeSignedTreeHead(readByteSlice(buf))
	if err != nil {
		return result, err
	}

	_ = binary.Read(buf, binary.BigEndian, &result.Index)

	result.Leaf, err = UnserializeTreeLeaf(readByteSlice(buf))
	if err != nil {
		return result, err
	}

	result.Hashes = readHashSlice(buf)

	return result, nil
}
