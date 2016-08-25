package main

import (
	"log"
	"fmt"
	"os"
	"sync"
	"net/http"
	"crypto/rand"
	//"encoding/base64"
	"encoding/hex"
	"golang.org/x/net/websocket"
	"golang.org/x/crypto/ssh/terminal"
	"github.com/twstrike/otr3"
)

const OTRFragmentSize = 140

type Talk struct {
	Conversation	*otr3.Conversation
	WebSocket	*websocket.Conn
	toSend		[]otr3.ValidMessage
	incoming	[]string
	outgoing	[]string
}


var (
	CurrentTalk	*Talk
	ToTerm		chan string
)

func OTRReceive(talk *Talk) {
	data := make([]byte, 512)
	for {
		n, err := talk.WebSocket.Read(data)
		if err != nil {
			//log.Printf("Unable to read data: %v", err)
			return
		}
		msg, toSend, err := talk.Conversation.Receive(data[:n])
		if err != nil {
			log.Printf("Unable to recieve OTR message: %v", err)
		}
		talk.toSend = append(talk.toSend, toSend...)
		//log.Printf("toSend from Receive: %v", toSend)
		if len(msg) > 0 {
			talk.incoming = append(talk.incoming, string(msg))

			toTerm := fmt.Sprintf("%x: %s", talk.Conversation.GetTheirKey().Fingerprint(), talk.incoming[0])
			log.Printf("%s", toTerm)
			talk.incoming = talk.incoming[1:]

		}
	}
}
func OTRSend(talk *Talk) {
	for {
		if len(talk.outgoing) > 0 {
			outMsg := talk.outgoing[0]
			talk.outgoing = talk.outgoing[1:]
			toSend, err := talk.Conversation.Send(otr3.ValidMessage(outMsg))
			if err != nil {
				log.Printf("Unable to process an outgoing message: %v", err)
			}
			if (len(outMsg) > 0) {
				log.Printf("> %s", outMsg)
			}
			talk.toSend = append(talk.toSend, toSend...)
		}
		//log.Printf("toSend: %v", talk.toSend)
		for (len(talk.toSend) > 0) {
			_, err := talk.WebSocket.Write(talk.toSend[0])
			if err != nil {
				log.Printf("Unable to write data: %v", err)
				return
			}
			talk.toSend = talk.toSend[1:]
		}
	}
}

func OTRHandler(privKey otr3.PrivateKey) websocket.Handler {
    return func(ws *websocket.Conn) {
	log.Printf("Got new connection")
	talk := &Talk{}
	CurrentTalk = talk
	talk.Conversation = &otr3.Conversation{}
	talk.Conversation.SetOurKeys([]otr3.PrivateKey{privKey})
	talk.Conversation.Policies.RequireEncryption()
	//c.Policies.AllowV2()
	talk.Conversation.Policies.AllowV3()
	talk.WebSocket = ws
	defer ws.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go OTRReceive(talk)
	go OTRSend(talk)

	wg.Wait()
}}


func main() {
	log.Printf("Welcome to tulip!")


	privKey := &otr3.DSAPrivateKey{}
	privKey.Generate(rand.Reader)
	//log.Printf(base64.RawStdEncoding.EncodeToString(privKey.Serialize(nil)))
	log.Println("Our fingerprint:", hex.EncodeToString(privKey.Fingerprint()))


	http.Handle("/tulip", websocket.Handler(OTRHandler(privKey)))
	http.Handle("/", http.FileServer(http.Dir("webroot")))

	go http.ListenAndServe(":8000", nil)
/*
	showIncoming := func() {
		for {
		}
	}
	go showIncoming()
*/
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldState)

	term := terminal.NewTerminal(os.Stdin, "")
	go func() {
		for {
			toTerm := <-ToTerm
			log.Printf("%s", toTerm)
			//term.Write([]byte(<-toTerm))
		}
	}()

	for {
		term.SetPrompt("> ")
		input, err := term.ReadLine()
		if err != nil {
			log.Fatalf("Unable to read line from terminal: %v", err)
		}
		CurrentTalk.outgoing = append(CurrentTalk.outgoing, input)
	}
}
