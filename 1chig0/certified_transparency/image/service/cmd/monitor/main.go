package main

import (
	"bytes"
	"certified-transparency/pkg"
	"certified-transparency/pkg/index"
	"certified-transparency/pkg/models"
	"certified-transparency/pkg/requests"
	"certified-transparency/pkg/storage"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/alecthomas/kingpin/v2"
	"log"
	"net/http"
	"time"
)

func respondJson(w http.ResponseWriter, response any) {
	data, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "cannot serialize response", http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(data)
	}
}

type Api struct {
	SignPublicKey []byte
	EncryptionKey []byte
}

func (api *Api) handlePubkey(w http.ResponseWriter, req *http.Request) {
	respondJson(w, requests.MetaResponse{api.SignPublicKey})
}

func (api *Api) handlePrivateClaim(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	request := &requests.PrivateClaimRequest{}
	err := json.NewDecoder(req.Body).Decode(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sot, err := models.UnserializeSignedOwnershipTimestamp(request.Sot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	claim, err := models.UnserializeTreeLeafProof(request.ClaimedLeaf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !pkg.VerifyOwnership(api.SignPublicKey, &sot) {
		http.Error(w, "invalid SOT", http.StatusBadRequest)
		return
	}
	if !pkg.VerifyTreeHead(api.SignPublicKey, &claim.Head) || !storage.VerifyLeafProofHashes(claim) {
		http.Error(w, "invalid leaf proof", http.StatusBadRequest)
		return
	}
	if !bytes.Equal(sot.Ownership.ContentHash[:], claim.Leaf.Ownership.ContentHash[:]) {
		http.Error(w, "this is not your content", http.StatusBadRequest)
		return
	}
	if !sot.Timestamp.Before(claim.Leaf.Created) {
		http.Error(w, "claimed content was first", http.StatusBadRequest)
		return
	}

	respondJson(w, requests.ClaimResponse{
		Granted: true,
		Data:    string(pkg.Decrypt(api.EncryptionKey, claim.Leaf.DataForPrivateClaims, pkg.DATA_FOR_PRIVATE_CLAIM)),
	})
}

func (api *Api) handlePublicClaim(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	request := &requests.PublicClaimRequest{}
	err := json.NewDecoder(req.Body).Decode(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	claimer, err := models.UnserializeTreeLeafProof(request.ClaimingLeaf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	claimed, err := models.UnserializeTreeLeafProof(request.ClaimedLeaf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !pkg.VerifyTreeHead(api.SignPublicKey, &claimer.Head) {
		http.Error(w, "invalid claiming leaf signature", http.StatusBadRequest)
		return
	}
	if !storage.VerifyLeafProofHashes(claimer) {
		http.Error(w, "invalid claiming leaf proof", http.StatusBadRequest)
		return
	}
	if !pkg.VerifyTreeHead(api.SignPublicKey, &claimed.Head) {
		http.Error(w, "invalid claimed leaf signature", http.StatusBadRequest)
		return
	}
	if !storage.VerifyLeafProofHashes(claimed) {
		http.Error(w, "invalid claimed leaf proof", http.StatusBadRequest)
		return
	}
	if !bytes.Equal(claimer.Leaf.Ownership.ContentHash[:], claimed.Leaf.Ownership.ContentHash[:]) {
		http.Error(w, "this is not your content", http.StatusBadRequest)
		return
	}
	if claimed.Index <= claimer.Index {
		http.Error(w, "claimed content was first", http.StatusBadRequest)
		return
	}
	if !pkg.VerifyLeaf(claimer.Leaf.PubKey, &claimer.Leaf, request.ClaimingLeafSignature) {
		http.Error(w, "invalid claiming leaf signature", http.StatusBadRequest)
		return
	}

	respondJson(w, requests.ClaimResponse{
		Granted: true,
		Data:    string(pkg.Decrypt(api.EncryptionKey, claimed.Leaf.DataForPublicClaims, pkg.DATA_FOR_PUBLIC_CLAIM)),
	})
}

func main() {
	host := kingpin.Flag("host", "Log server to monitor").Default("http://127.0.0.1:3000").String()
	kingpin.Parse()

	logApiClient := requests.NewLogApiClient(*host)
	pubkey, err := logApiClient.GetPubkey()
	if err != nil {
		time.Sleep(2 * time.Second)
		pubkey, err = logApiClient.GetPubkey()
		if err != nil {
			log.Fatalf("could not fetch public key from %q: %v\n", logApiClient.Host, err)
		}
	}

	enckey := storage.LoadEncryptionKey()
	monitorServerApi := Api{
		SignPublicKey: pubkey,
		EncryptionKey: enckey,
	}

	sockets := NewWebSocketPool()
	go func() {
		err := WatchServer(logApiClient, sockets)
		log.Fatal(err)
	}()
	log.Printf("Monitoring %q with pubkey %s...\n", logApiClient.Host, hex.EncodeToString(pubkey))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/get-pubkey", monitorServerApi.handlePubkey)
	mux.HandleFunc("/api/v1/claim-private", monitorServerApi.handlePrivateClaim)
	mux.HandleFunc("/api/v1/claim-public", monitorServerApi.handlePublicClaim)
	mux.HandleFunc("/api/v1/watch", sockets.WebsocketHandler)

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(index.IndexFile)
	})

	err = http.ListenAndServe(":3001", mux)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
