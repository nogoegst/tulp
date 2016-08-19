package main

import (
	"log"
	"net/http"
	"crypto/rand"
	//"encoding/base64"
	"encoding/hex"
	"golang.org/x/net/websocket"
	"github.com/twstrike/otr3"
)

const OTRFragmentSize = 140

func OTRHandler(privKey otr3.PrivateKey) websocket.Handler {
    return func(ws *websocket.Conn) {
	log.Printf("Got new connection. Awaiting OTR init from the source...")
	conv := &otr3.Conversation{}
	conv.SetOurKeys([]otr3.PrivateKey{privKey})
	conv.Policies.RequireEncryption()
	//c.Policies.AllowV2()
	conv.Policies.AllowV3()

	for {
		data := make([]byte, 512)
		n, err := ws.Read(data)
		if err != nil {
			log.Printf("Unable to read data: %v", err)
			goto Exit
		}
		msg, toSend, err := conv.Receive(data[:n])
		if err != nil {
			log.Printf("Unable to recieve OTR message: %v", err)
		}
		/*switch OTRSecChange {
		case otr.NewKeys:
			log.Println("Their fingerprint:", hex.EncodeToString(conv.TheirPublicKey.Fingerprint()))
		}*/
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
}}


func main() {
	log.Printf("Welcome to tulip!")

	privKey := &otr3.DSAPrivateKey{}
	privKey.Generate(rand.Reader)
	//log.Printf(base64.RawStdEncoding.EncodeToString(privKey.Serialize(nil)))
	log.Println("Our fingerprint:", hex.EncodeToString(privKey.Fingerprint()))


	http.Handle("/tulip", websocket.Handler(OTRHandler(privKey)))
	http.Handle("/", http.FileServer(http.Dir("webroot")))

	log.Fatal(http.ListenAndServe(":8000", nil))
}
