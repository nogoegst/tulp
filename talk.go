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
	toSend        []otr3.ValidMessage
	incoming      []string
	outgoing      []string
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
			goto Finish
		}
		if err != nil {
			goto Finish
		}
		msg, toSend, err := talk.Conversation.Receive(data)
		if err != nil {
			log.Printf("Unable to recieve OTR message: %v", err)
		}
		talk.toSend = append(talk.toSend, toSend...)
		if len(msg) > 0 {
			talk.incoming = append(talk.incoming, string(msg))
			toTerm := fmt.Sprintf("%s: %s", talk.GetBestName(), talk.incoming[0])
			ToTerm <- toTerm
			talk.incoming = talk.incoming[1:]

		}
	}
Finish:
	talk.finished = true
}

func (talk *Talk) OTRSendLoop() {
	for !talk.finished {
		if len(talk.outgoing) > 0 {
			outMsg := talk.outgoing[0]
			talk.outgoing = talk.outgoing[1:]
			toSend, err := talk.Conversation.Send(otr3.ValidMessage(outMsg))
			if err != nil {
				log.Printf("Unable to process an outgoing message: %v", err)
			}
			talk.toSend = append(talk.toSend, toSend...)
		}
		for len(talk.toSend) > 0 {
			err := talk.WebSocket.WriteMessage(websocket.TextMessage,
				talk.toSend[0])
			if err != nil {
				goto Finish
			}
			talk.toSend = talk.toSend[1:]
		}
	}
Finish:
	talk.finished = true
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

