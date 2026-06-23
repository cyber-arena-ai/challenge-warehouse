package main

import (
	"certified-transparency/pkg"
	"certified-transparency/pkg/index"
	"certified-transparency/pkg/models"
	"certified-transparency/pkg/requests"
	"certified-transparency/pkg/storage"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
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
	Tree           *storage.MerkleTree
	SignPublicKey  ed25519.PublicKey
	SignPrivateKey ed25519.PrivateKey
	EncryptionKey  []byte
}

func (api *Api) handlePubkey(w http.ResponseWriter, req *http.Request) {
	respondJson(w, requests.MetaResponse{api.SignPublicKey})
}

func (api *Api) handleSth(w http.ResponseWriter, req *http.Request) {
	sth := api.Tree.Head()
	pkg.SignTreeHead(api.SignPrivateKey, &sth)
	respondJson(w, requests.SthResponse{sth.Serialize()})
}

func (api *Api) handleAddEntry(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	request := &requests.AddEntryRequest{}
	err := json.NewDecoder(req.Body).Decode(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	leaf := models.TreeLeaf{
		Created: time.Now(),
		Ownership: models.Ownership{
			ContentHash: models.ToHash(request.ContentHash),
			Name:        request.Name,
		},
		PubKey:               request.PubKey,
		DataForPrivateClaims: pkg.Encrypt(api.EncryptionKey, []byte(request.DataForPrivateClaims), pkg.DATA_FOR_PRIVATE_CLAIM),
		DataForPublicClaims:  pkg.Encrypt(api.EncryptionKey, []byte(request.DataForPublicClaims), pkg.DATA_FOR_PUBLIC_CLAIM),
	}
	index, err := api.Tree.Append(leaf)
	log.Printf("Added entry %d in %.1fms\n", index, float64(time.Since(leaf.Created).Microseconds())/1000.0)

	respondJson(w, requests.AddEntryResponse{index})
}

func (api *Api) handleSignEntry(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sot := models.SignedOwnershipTimestamp{
		Timestamp: time.Now(),
	}

	err := json.NewDecoder(req.Body).Decode(&models.JsonOwnership{Ref: &sot.Ownership})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pkg.SignOwnership(api.SignPrivateKey, &sot)

	respondJson(w, requests.SignEntryResponse{sot.Serialize()})
}

func (api *Api) handleGetEntries(w http.ResponseWriter, req *http.Request) {
	start, err1 := strconv.Atoi(req.URL.Query().Get("start"))
	end, err2 := strconv.Atoi(req.URL.Query().Get("end"))
	if err1 != nil || err2 != nil || start < 0 || end <= start || end-start > 16 || uint64(start) >= api.Tree.Size() {
		http.Error(w, "invalid parameters", http.StatusBadRequest)
		return
	}

	response := requests.GetEntriesResponse{make([][]byte, 0)}

	for i := uint64(start); i < uint64(end) && i < api.Tree.Size(); i++ {
		leaf, err := api.Tree.GetLeaf(i)
		if err != nil || leaf == nil {
			log.Printf("GetLeaf: %v\n", err)
			http.Error(w, "cannot retrieve entry", http.StatusInternalServerError)
			return
		}
		response.Leaves = append(response.Leaves, leaf.Serialize())
	}

	respondJson(w, response)
}

func (api *Api) handleGetEntryAndProof(w http.ResponseWriter, req *http.Request) {
	index, err := strconv.Atoi(req.URL.Query().Get("leaf_index"))
	if err != nil || index < 0 || uint64(index) >= api.Tree.Size() {
		http.Error(w, "invalid parameters", http.StatusBadRequest)
		return
	}

	proof, err := api.Tree.GetLeafProof(uint64(index))
	if err != nil {
		http.Error(w, "cannot retrieve proof", http.StatusInternalServerError)
		return
	}

	pkg.SignTreeHead(api.SignPrivateKey, &proof.Head)

	respondJson(w, requests.GetEntryAndProofResponse{proof.Serialize()})
}

func main() {
	repository := storage.OpenRepository()
	defer repository.Close()
	tree := storage.NewMerkleTree(repository)
	pubkey, privkey := storage.LoadSignKeys()
	enckey := storage.LoadEncryptionKey()
	api := Api{
		Tree:           tree,
		SignPublicKey:  pubkey,
		SignPrivateKey: privkey,
		EncryptionKey:  enckey,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/get-pubkey", api.handlePubkey)
	mux.HandleFunc("/api/v1/get-sth", api.handleSth)
	mux.HandleFunc("/api/v1/add-entry", api.handleAddEntry)
	mux.HandleFunc("/api/v1/sign-entry", api.handleSignEntry)
	mux.HandleFunc("/api/v1/get-entries", api.handleGetEntries)
	mux.HandleFunc("/api/v1/get-entry-and-proof", api.handleGetEntryAndProof)

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write(index.IndexFile)
	})

	err := http.ListenAndServe(":3000", mux)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
