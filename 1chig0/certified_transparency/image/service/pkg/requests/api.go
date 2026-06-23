package requests

import (
	"bytes"
	"certified-transparency/pkg/models"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type ApiClient struct {
	client http.Client
	Host   string
}

type LogApiClient struct {
	ApiClient
}

type MonitorApiClient struct {
	ApiClient
}

func NewLogApiClient(host string) *LogApiClient {
	return &LogApiClient{ApiClient{
		client: http.Client{Timeout: 7 * time.Second},
		Host:   host,
	}}
}

func NewMonitorApiClient(host string) *MonitorApiClient {
	return &MonitorApiClient{ApiClient{
		client: http.Client{Timeout: 7 * time.Second},
		Host:   host,
	}}
}

func (api *ApiClient) GetPubkey() (ed25519.PublicKey, error) {
	resp, err := api.client.Get(fmt.Sprintf("%s/api/v1/get-pubkey", api.Host))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get-pubkey: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response MetaResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return response.Pubkey, nil
}

func (api *LogApiClient) GetSth() (models.SignedTreeHead, error) {
	resp, err := api.client.Get(fmt.Sprintf("%s/api/v1/get-sth", api.Host))
	if err != nil {
		return models.SignedTreeHead{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return models.SignedTreeHead{}, fmt.Errorf("get-sth: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response SthResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return models.SignedTreeHead{}, err
	}

	return models.UnserializeSignedTreeHead(response.Sth)
}

func (api *LogApiClient) GetEntries(start uint64, end uint64) ([]models.TreeLeaf, error) {
	resp, err := api.client.Get(fmt.Sprintf("%s/api/v1/get-entries?start=%d&end=%d", api.Host, start, end))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get-entries: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response GetEntriesResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	entries := make([]models.TreeLeaf, len(response.Leaves))
	for i, leaf := range response.Leaves {
		entries[i], err = models.UnserializeTreeLeaf(leaf)
		if err != nil {
			return nil, err
		}
	}

	return entries, nil
}

func (api *LogApiClient) GetEntryAndProof(index uint64) (models.TreeLeafProof, error) {
	resp, err := api.client.Get(fmt.Sprintf("%s/api/v1/get-entry-and-proof?leaf_index=%d", api.Host, index))
	if err != nil {
		return models.TreeLeafProof{}, errors.Wrap(err, "get-entry-and-proof")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return models.TreeLeafProof{}, fmt.Errorf("get-entry-and-proof: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response GetEntryAndProofResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return models.TreeLeafProof{}, errors.Wrap(err, "get-entry-and-proof")
	}

	return models.UnserializeTreeLeafProof(response.Proof)
}

func (api *LogApiClient) AddEntry(request AddEntryRequest) (uint64, error) {
	body, _ := json.Marshal(request)
	resp, err := api.client.Post(fmt.Sprintf("%s/api/v1/add-entry", api.Host),
		"application/json", bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("add-entry: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response AddEntryResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	return response.Index, err
}

func (api *LogApiClient) SignEntry(ownership models.Ownership) (models.SignedOwnershipTimestamp, error) {
	body, _ := json.Marshal(models.JsonOwnership{Ref: &ownership})
	resp, err := api.client.Post(fmt.Sprintf("%s/api/v1/sign-entry", api.Host),
		"application/json", bytes.NewBuffer(body))
	if err != nil {
		return models.SignedOwnershipTimestamp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return models.SignedOwnershipTimestamp{}, fmt.Errorf("sign-entry: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response SignEntryResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return models.SignedOwnershipTimestamp{}, err
	}

	return models.UnserializeSignedOwnershipTimestamp(response.Sot)
}

func (api *MonitorApiClient) ClaimPrivate(sot models.SignedOwnershipTimestamp, claimed models.TreeLeafProof) (ClaimResponse, error) {
	body, _ := json.Marshal(PrivateClaimRequest{
		Sot:         sot.Serialize(),
		ClaimedLeaf: claimed.Serialize(),
	})
	resp, err := api.client.Post(fmt.Sprintf("%s/api/v1/claim-private", api.Host),
		"application/json", bytes.NewBuffer(body))
	if err != nil {
		return ClaimResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return ClaimResponse{}, fmt.Errorf("claim-private: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response ClaimResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return ClaimResponse{}, err
	}

	return response, nil
}

func (api *MonitorApiClient) ClaimPublic(claiming models.TreeLeafProof, claimed models.TreeLeafProof, claimingLeafSignature []byte) (ClaimResponse, error) {
	body, _ := json.Marshal(PublicClaimRequest{
		ClaimingLeaf:          claiming.Serialize(),
		ClaimedLeaf:           claimed.Serialize(),
		ClaimingLeafSignature: claimingLeafSignature,
	})
	resp, err := api.client.Post(fmt.Sprintf("%s/api/v1/claim-public", api.Host),
		"application/json", bytes.NewBuffer(body))
	if err != nil {
		return ClaimResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		text, _ := io.ReadAll(resp.Body)
		return ClaimResponse{}, fmt.Errorf("claim-public: status %d (%s)", resp.StatusCode, strings.TrimSpace(string(text)))
	}

	var response ClaimResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return ClaimResponse{}, err
	}

	return response, nil
}

func (api *MonitorApiClient) Monitor(output chan NewLeafMessage) error {
	defer close(output)

	url := fmt.Sprintf("%s/api/v1/watch", strings.Replace(api.Host, "http", "ws", 1))
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			<-ticker.C
			err = c.WriteMessage(websocket.PingMessage, []byte{})
			if err != nil {
				if !websocket.IsCloseError(err) {
					log.Printf("ping error: %v", err)
				}
				return
			}
		}
	}()

	for {
		_ = c.SetReadDeadline(time.Now().Add(32 * time.Second))
		mt, message, err := c.ReadMessage()
		if err != nil {
			return err
		}
		if mt == websocket.TextMessage {
			var msg NewLeafMessage
			err = json.Unmarshal(message, &msg)
			if err != nil {
				return err
			}
			output <- msg
		}
	}
}
