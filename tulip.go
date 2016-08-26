package main

import (
	"log"
	"fmt"
	"os"
	"strings"
	"bytes"
	"sync"
	"strconv"
	"flag"
	"net"
	"net/http"
	"crypto/rand"
	//"encoding/base64"
	"encoding/hex"
	"bulb"
	bulb_utils "bulb/utils"
	"github.com/gorilla/websocket"
	"h12.me/socks"
	//"golang.org/x/net/websocket"
	"golang.org/x/crypto/ssh/terminal"
	"github.com/twstrike/otr3"
)

const OTRFragmentSize = 140

type Person struct {
        OTRFingerprints         [][]byte
        OnionAddresses          []string
}

type AddressBook map[string]Person

func LookUpAddressBookByFingerprint(abook *AddressBook, FP []byte) (name string) {
	for name, person := range *abook {
		for _, fp := range person.OTRFingerprints {
			if bytes.Equal(fp, FP) {
				return name
			}
		}
	}
	return name
}


type Talk struct {
	Conversation	*otr3.Conversation
	WebSocket	*websocket.Conn
	wg		*sync.WaitGroup
	toSend		[]otr3.ValidMessage
	incoming	[]string
	outgoing	[]string
	finished	bool
}

func getBestName(talk *Talk) (name string) {
	fp := talk.Conversation.GetTheirKey().Fingerprint()
	name = LookUpAddressBookByFingerprint(&addressBook, fp)
	if (name=="") {
		name = fmt.Sprintf("%x", fp)
	}
	return name
}

var (
	privKey		*otr3.DSAPrivateKey
	addressBook =	make(AddressBook)
	activeTalks	[]*Talk
	CurrentTalk	*Talk
	ToTerm		chan string
	upgrader =	websocket.Upgrader{}
)

func OTRReceive(talk *Talk) {
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
			toTerm := fmt.Sprintf("%s: %s", getBestName(talk), talk.incoming[0])
			log.Printf("%s", toTerm)
			talk.incoming = talk.incoming[1:]

		}
	}
   Finish:
	talk.finished = true
	talk.wg.Done()
}
func OTRSend(talk *Talk) {
	for !talk.finished {
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
		for (len(talk.toSend) > 0) {
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
	talk.wg.Done()
}

func StartTalk(ws *websocket.Conn) {
	talk := &Talk{}
	activeTalks = append(activeTalks, talk)
	CurrentTalk = talk
	talk.Conversation = &otr3.Conversation{}
	talk.Conversation.SetOurKeys([]otr3.PrivateKey{privKey})
	talk.Conversation.Policies.RequireEncryption()
	//c.Policies.AllowV2()
	talk.Conversation.Policies.AllowV3()
	talk.WebSocket = ws

	var wg sync.WaitGroup
	talk.wg = &wg
	wg.Add(2)

	go OTRReceive(talk)
	go OTRSend(talk)

	wg.Wait()
	log.Printf("Ended talk")
}
func IncomingTalkHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Unable to upgrade: %v", err)
		return
	}
	defer ws.Close()
	log.Printf("Got new connection")
	StartTalk(ws)
}

func GetPort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func main() {
	var debug_flag = flag.Bool("debug", false,
		"Show what's happening")
	var control = flag.String("control-addr", "tcp://127.0.0.1:9051",
		"Set Tor control address to be used")
	var control_passwd = flag.String("control-passwd", "",
		"Set Tor control auth password")
	flag.Parse()
	debug := *debug_flag

	log.Printf("Welcome to tulip!")
    // Parse control string
    control_net, control_addr, err := bulb_utils.ParseControlPortString(*control)
    if err != nil {
        log.Fatalf("Failed to parse Tor control address string: %v", err)
    }
    // Connect to a running tor instance.
    c, err := bulb.Dial(control_net, control_addr)
	if err != nil {
		log.Fatalf("Failed to connect to control socket: %v", err)
	}
	defer c.Close()

	// See what's really going on under the hood.
	// Do not enable in production.
	c.Debug(debug)

	// Authenticate with the control port.  The password argument
	// here can be "" if no password is set (CookieAuth, no auth).
	if err := c.Authenticate(*control_passwd); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// At this point, c.Request() can be used to issue requests.
	resp, err := c.Request("GETINFO version")
	if err != nil {
		log.Fatalf("GETINFO version failed: %v", err)
	}
	log.Printf("We're using tor %v", resp.Data[0])

	c.StartAsyncReader()


	privKey = &otr3.DSAPrivateKey{}
	privKey.Generate(rand.Reader)
	//log.Printf(base64.RawStdEncoding.EncodeToString(privKey.Serialize(nil)))
	log.Println("Our fingerprint:", hex.EncodeToString(privKey.Fingerprint()))

	browserFP, _ := hex.DecodeString("2264d806e7789a5773bdaffb798bcf3fdb456a81")
	browserP := Person{OTRFingerprints: [][]byte{browserFP}}
	addressBook["browser"] = browserP
	log.Print(addressBook)



	http.HandleFunc("/tulip", IncomingTalkHandler)
	http.Handle("/", http.FileServer(http.Dir("webroot")))

	freePort := GetPort()
	log.Printf("gotPort: %d", freePort)
	go http.ListenAndServe(fmt.Sprintf(":%d", freePort), nil)//tring(freePort), nil)


	onionPortSpec := []bulb.OnionPortSpec{bulb.OnionPortSpec{80,
                           strconv.FormatUint((uint64)(freePort), 10)}}
	onionInfo, err := c.AddOnion(onionPortSpec, nil, true)
	if err != nil {
		log.Fatalf("Error occured: %v", err)
	}
	log.Printf("You're at %v.onion", onionInfo.OnionID)
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
		if strings.HasPrefix(input, "/") {
			cmdLine := strings.TrimPrefix(input, "/")
			args := strings.Split(cmdLine, " ")
			switch args[0] {
			case "list":
				for _, talk := range activeTalks {
					log.Printf("[*] %s", getBestName(talk))
				}
			case "connect":
				if !strings.HasSuffix(args[1], ".onion") { //check existence!
					log.Printf("It's not an onion address.")
					break
				}
				onionAddress := args[1]
				origin := "http://"+onionAddress+"/"
				url := "ws://"+onionAddress+"/tulip"
				torDial := socks.DialSocksProxy(socks.SOCKS5, "127.0.0.1:9050")
				dialer := websocket.Dialer{NetDial: torDial}
				requestHeader := make(http.Header)
				requestHeader.Set("Origin", origin)
				ws, _, err := dialer.Dial(url, requestHeader)
				if err != nil {
					log.Printf("Unable to connect")
					break
				}
				go StartTalk(ws)
			default:
				log.Printf("No such command.")
			}
			continue
		}
		if (CurrentTalk != nil) {
			CurrentTalk.outgoing = append(CurrentTalk.outgoing, input)
		} else {
			log.Printf("There is no active talk.")
		}
	}
}
