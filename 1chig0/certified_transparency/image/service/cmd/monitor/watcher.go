package main

import (
	"certified-transparency/pkg/models"
	"certified-transparency/pkg/requests"
	"encoding/json"
	"github.com/gorilla/websocket"
	"log"
	"time"
)

func WatchServer(api *requests.LogApiClient, pool *WebSocketPool) error {
	sth, err := api.GetSth()
	if err != nil {
		return err
	}
	currentPos := sth.Size
	log.Printf("current log size: %d\n", sth.Size)

	for {
		time.Sleep(2 * time.Second)
		sth, err = api.GetSth()
		if err != nil {
			return err
		}

		for currentPos < sth.Size {
			end := currentPos + 16
			if end > sth.Size {
				end = sth.Size
			}
			entries, err := api.GetEntries(currentPos, end)
			if err != nil {
				return err
			}

			for _, entry := range entries {
				err = announceNewLeaf(currentPos, entry, pool)
				if err != nil {
					return err
				}
				currentPos += 1
			}
		}
	}
}

func announceNewLeaf(index uint64, leaf models.TreeLeaf, pool *WebSocketPool) error {
	msg, err := json.Marshal(requests.NewLeafMessage{
		Index: index,
		Leaf:  leaf.Serialize(),
	})
	if err != nil {
		return err
	}
	pm, err := websocket.NewPreparedMessage(websocket.TextMessage, msg)
	if err != nil {
		return err
	}
	pool.Broadcast(pm)
	return nil
}
