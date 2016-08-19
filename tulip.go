package main

import (
	"log"
	"net/http"
	"crypto/rand"
	//"encoding/base64"
	"encoding/hex"
	"golang.org/x/net/websocket"
	"golang.org/x/crypto/otr"
)

const OTRFragmentSize = 140

func echoHandler(ws *websocket.Conn) {
	privKey := otr.PrivateKey{}
	privKey.Generate(rand.Reader)
	//log.Printf(base64.RawStdEncoding.EncodeToString(privKey.Serialize(nil)))
	log.Println("Our fingerprint:", hex.EncodeToString(privKey.Fingerprint()))
	conv := otr.Conversation{PrivateKey: &privKey, FragmentSize: OTRFragmentSize}
	for {
		data := make([]byte, 512)
		n, err := ws.Read(data)
		if err != nil {
			log.Printf("Unable to read data: %v", err)
			goto Exit
		}
		log.Printf("Payload type: %d", ws.PayloadType)
		msg, _, OTRSecChange, toSend, err := conv.Receive(data[:n])
		if err != nil {
			log.Printf("Unable to recieve OTR message: %v", err)
		}
		switch OTRSecChange {
		case otr.NewKeys:
			log.Println("Their fingerprint:", hex.EncodeToString(conv.TheirPublicKey.Fingerprint()))
		}
		if len(msg) > 0 {
			log.Printf("> %s", msg)
		}
		for _, outMsg := range toSend {
			_, err = ws.Write(outMsg)
			if err != nil {
				log.Printf("Unable to read data: %v", err)
				goto Exit
			}
		}
	}
        Exit:
	 defer ws.Close()
}


func main() {
	log.Printf("Welcome to tulip!")
	http.Handle("/tulip", websocket.Handler(echoHandler))
	http.Handle("/", http.FileServer(http.Dir("webroot")))

	log.Fatal(http.ListenAndServe(":8000", nil))
}
