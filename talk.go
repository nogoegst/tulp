package main

import (
	"fmt"
	"log"

	"github.com/gorilla/websocket"
	"github.com/twstrike/otr3"

)

const OTRFragmentSize = 140

type Talk struct {
	lastKnownName string
	Conversation  *otr3.Conversation
	WebSocket     *websocket.Conn
	toSend        chan otr3.ValidMessage
	incoming      chan string
	outgoing      chan string
	finished      bool
}

func (talk *Talk) GetBestName() (name string) {
	theirKey := talk.Conversation.GetTheirKey()
	if theirKey != nil {
		fp := theirKey.Fingerprint()
		name = LookUpAddressBookByFingerprint(&addressBook, fp)
		if name == "" {
			name = fmt.Sprintf("%x", fp)
		}
	}
	talk.lastKnownName = name
	return name
}

var (
	privKey     *otr3.DSAPrivateKey
	addressBook = make(AddressBook)
	activeTalks = make(map[string]*Talk)
	ToTerm      = make(chan string)
	upgrader    = websocket.Upgrader{}
)

func (talk *Talk) OTRReceiveLoop() {
	for !talk.finished {
		mt, data, err := talk.WebSocket.ReadMessage()
		if mt != websocket.TextMessage {
			talk.finished = true
			continue
		}
		if err != nil {
			talk.finished = true
			continue
		}
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
	}
}

func (talk *Talk) OTRSendLoop() {
	go func(){
		for !talk.finished {
			outMsg := <-talk.outgoing
			toSend, err := talk.Conversation.Send(otr3.ValidMessage(outMsg))
			if err != nil {
				log.Printf("Unable to process an outgoing message: %v", err)
			}
			for _, ciphertext := range toSend {
				talk.toSend <- ciphertext
			}
		}
	}()
	go func(){
		for !talk.finished {
			msgToSend := <-talk.toSend
			err := talk.WebSocket.WriteMessage(websocket.TextMessage,
				msgToSend)
			if err != nil {
				talk.finished = true
				continue
			}
		}
	}()
}

func (talk *Talk) HandleSecurityEvent(event otr3.SecurityEvent) {
	switch event {
	case otr3.GoneSecure:
		activeTalks[talk.GetBestName()] = talk
	case otr3.GoneInsecure:
		delete(activeTalks, talk.lastKnownName)
		talk.finished = true
	}
}

