package requests

type PrivateClaimRequest struct {
	Sot         []byte `json:"sot"`
	ClaimedLeaf []byte `json:"claimed_leaf"`
}

type PublicClaimRequest struct {
	ClaimingLeaf          []byte `json:"claiming_leaf"`
	ClaimedLeaf           []byte `json:"claimed_leaf"`
	ClaimingLeafSignature []byte `json:"claiming_leaf_signature"`
}

type ClaimResponse struct {
	Granted bool   `json:"granted"`
	Data    string `json:"data"`
}

type NewLeafMessage struct {
	Index uint64 `json:"index"`
	Leaf  []byte `json:"leaf"`
}
