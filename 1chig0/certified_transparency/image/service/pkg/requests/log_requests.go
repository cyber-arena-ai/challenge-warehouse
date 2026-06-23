package requests

import "certified-transparency/pkg/models"

type MetaResponse struct {
	Pubkey []byte `json:"pubkey"`
}

type SthResponse struct {
	Sth []byte `json:"sth"`
}

type AddEntryRequest struct {
	ContentHash          []byte `json:"content_hash"`
	Name                 string `json:"name"`
	PubKey               []byte `json:"pubkey"`
	DataForPrivateClaims string `json:"data_private"`
	DataForPublicClaims  string `json:"data_public"`
}

type AddEntryResponse struct {
	Index uint64 `json:"index"`
}

type SignEntryRequest = models.Ownership

type SignEntryResponse struct {
	Sot []byte `json:"sot"`
}

type GetEntriesResponse struct {
	Leaves [][]byte `json:"leaves"`
}

type GetEntryAndProofResponse struct {
	Proof []byte `json:"proof"`
}
