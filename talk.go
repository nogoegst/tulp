package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gorilla/websocket"
	"github.com/twstrike/otr3"

)

const OTRFragmentSize = 140
const messageBacklog = 64

type Talk struct {
	lastKnownName string
	Conversation  *otr3.Conversation
	WebSocket     *websocket.Conn
	toSend        chan otr3.ValidMessage
	incoming      chan string
	outgoing      chan string
	active      chan bool
}


func NewTalk(ws *websocket.Conn) (talk *Talk) {
	talk = &Talk{}

	talk.outgoing = make(chan string, messageBacklog)
	talk.incoming = make(chan string, messageBacklog)
	talk.toSend = make(chan otr3.ValidMessage, messageBacklog)
	talk.active = make(chan bool)

	talk.WebSocket = ws

	conversation := &otr3.Conversation{}
	conversation.SetOurKeys([]otr3.PrivateKey{privKey})
	conversation.Policies.RequireEncryption()
	conversation.Policies.AllowV3()
	conversation.SetSecurityEventHandler(talk)
	talk.Conversation = conversation

	go talk.TalkLoop()
	return talk
}

func (talk *Talk) GetBestName() (name string) {
	theirKey := talk.Conversation.GetTheirKey()
	if theirKey != nil {
		fp := fmt.Sprintf("%x", theirKey.Fingerprint())
		name = LookUpAddressBookByEntryValue(&addressBook, fp)
		if name == "" {
			name = fp
		}
	}
	talk.lastKnownName = name
	return name
}

func (talk *Talk) TalkLoop() {
	go talk.ReceiveLoop()
	go talk.SendLoop()

	<-talk.active
	talk.WebSocket.Close()
	// If there was an OTR session
	if talk.lastKnownName != "" {
		connectEventChan <-ConnectEvent{connected: false, talk: talk}
	}
}

func (talk *Talk) ReceiveLoop() {
	for {
	select {
	case active := <-talk.active:
		if !active {
			return
		}
	default:
		mt, data, err := talk.WebSocket.ReadMessage()
		if err != nil {
			close(talk.active)
			return
		}
		switch(mt) {
		case websocket.TextMessage:
			msg, toSend, err := talk.Conversation.Receive(data)
			if err != nil {
				log.Printf("Unable to recieve OTR message: %v", err)
			}
			for _, ciphertext := range toSend {
				talk.toSend <- ciphertext
			}
			if len(msg) > 0 {
				talk.incoming <- string(msg)
			}
		default:
			log.Printf("Unknown ws frame recieved\n\r")
		}
	}
	}
}

func (talk *Talk) SendLoop() {
	for {
		ticker := time.NewTicker(2*time.Second)
		select {
		case active := <-talk.active:
			if !active {
				return
			}
		case outMsg := <-talk.outgoing:
			toSend, err := talk.Conversation.Send(otr3.ValidMessage(outMsg))
			if err != nil {
				log.Printf("Unable to process an outgoing message: %v", err)
			}
			for _, ciphertext := range toSend {
				talk.toSend <- ciphertext
			}
		case msgToSend := <-talk.toSend:
			err := talk.WebSocket.WriteMessage(websocket.TextMessage,
				msgToSend)
			if err != nil {
				close(talk.active)
				return
			}
		case <-ticker.C:
			talk.WebSocket.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(time.Second))
			ticker.Stop()
			ticker = time.NewTicker(2*time.Second)
		}
	}
}

type ConnectEvent struct {
	connected	bool
	talk		*Talk
}


func (talk *Talk) HandleSecurityEvent(event otr3.SecurityEvent) {
	switch event {
	case otr3.GoneSecure:
		connectEventChan <- ConnectEvent{connected: true, talk: talk}
	case otr3.GoneInsecure:
		close(talk.active)
	}
}

