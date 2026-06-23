package main

import (
	"errors"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"sync"
	"time"
)

var (
	pongWait  = 60 * time.Second
	writeWait = 7 * time.Second
	upgrader  = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

type WebSocketClient struct {
	writeLock sync.Mutex
	ws        *websocket.Conn
}

type WebSocketPool struct {
	lock    sync.Mutex
	Sockets map[*WebSocketClient]bool
}

func NewWebSocketPool() *WebSocketPool {
	return &WebSocketPool{
		Sockets: map[*WebSocketClient]bool{},
	}
}

func (monitor *WebSocketPool) RegisterConnection(ws *WebSocketClient) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()
	monitor.Sockets[ws] = true
}

func (monitor *WebSocketPool) UnregisterConnection(ws *WebSocketClient) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()
	delete(monitor.Sockets, ws)
}

func (monitor *WebSocketPool) Broadcast(message *websocket.PreparedMessage) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()
	for client := range monitor.Sockets {
		client := client
		go func() {
			client.writeLock.Lock()
			defer client.writeLock.Unlock()
			_ = client.ws.SetWriteDeadline(time.Now().Add(writeWait))
			err := client.ws.WritePreparedMessage(message)
			if err != nil {
				_ = client.ws.Close()
				monitor.UnregisterConnection(client)
			}
		}()
	}
}

func (monitor *WebSocketPool) WebsocketHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		var handshakeError websocket.HandshakeError
		if !errors.As(err, &handshakeError) {
			log.Println(err)
		}
		return
	}

	defer ws.Close()
	client := &WebSocketClient{ws: ws}
	monitor.RegisterConnection(client)
	defer monitor.UnregisterConnection(client)

	_ = ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, _, err = ws.ReadMessage()
		if err != nil {
			break
		}
	}
}
