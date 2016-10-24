package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/nogoegst/onionutil"
	"github.com/gorilla/websocket"
	"github.com/twstrike/otr3"
	"golang.org/x/crypto/ssh/terminal"
)

var(
	term *terminal.Terminal
	upgrader = websocket.Upgrader{}
	activeTalks = make(map[string]*Talk)
	connectEvent = make(chan string)
	privKey     *otr3.DSAPrivateKey
	addressBook = make(AddressBook)
)

func updateTalkMap() {
	for key, talk := range activeTalks {
		newKey := talk.GetBestName()
		if key != newKey {
			delete(activeTalks, key)
			activeTalks[newKey] = talk
		}
	}
}

func IncomingTalkHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		warn(term, "Unable to upgrade: %v", err)
		return
	}
	info(term, "New ws connection")
	talk := NewTalk(ws)
	// Collect messages to terminal
	go func(){
		for {
			inMsg := <-talk.incoming
			info(term, "%s : %s", talk.GetBestName(), inMsg)
		}
	}()
}

func connectToOnion(torConfig TorConfig, onionAddress string) () {
	url := "ws://" + onionAddress + "/tulip"
	torDialer, err := torConfig.GetTorDialer()
	if err != nil {
		return
	}
	dialer := websocket.Dialer{NetDial: torDialer.Dial}
	requestHeader := make(http.Header)
	ws, _, err := dialer.Dial(url, requestHeader)
	if err != nil {
		alert(term, "Unable to connect")
		return
	}
	talk := NewTalk(ws)
	talk.outgoing <- ""
}

func main() {
	var debugFlag = flag.Bool("debug", false,
		"Show what's happening")
	var noOnionFlag = flag.Bool("no-onion", false,
		"Run without making onion address")
	var control = flag.String("control-addr", "tcp://127.0.0.1:9151",
		"Set Tor control address to be used")
	var proxyAddr = flag.String("proxy-addr", "127.0.0.1:9150",
		"Set Tor control address to be used")
	var controlPassword = flag.String("control-passwd", "",
		"Set Tor control auth password")
	flag.Parse()
	debug := *debugFlag

	torConfig := TorConfig{SocksAddr: *proxyAddr, Control: *control, ControlPassword: *controlPassword, Debug: debug}

	oldTermState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldTermState)

	term = terminal.NewTerminal(os.Stdin, "")


	term.SetBracketedPasteMode(true)
	defer term.SetBracketedPasteMode(false)

	info(term, "Welcome to tulip!")

	localPort := strconv.FormatUint((uint64) (GetPort()), 10)
	if !(*noOnionFlag) {
		onionAddr, err := torConfig.MakeOnion(localPort)
		if err != nil {
			critical(term, "%v", err)
		}
		info(term, "You're at %v.onion", onionAddr)
	}

	otrPassphrase, err := term.ReadPassword(fmt.Sprintf("Enter your passphrase for OTR identity: "))
	if err != nil {
		critical(term, "Unable to read OTR passphrase: %v", err)
	}

	privKey = &otr3.DSAPrivateKey{}
	err = privKey.Generate(onionutil.KeystreamReader([]byte(otrPassphrase), []byte("tulp-otr-keygen")))
	if err != nil {
		critical(term, "Unable to generate DSA key: %v", err)
	}
	info(term, "Our fingerprint: %x", privKey.Fingerprint())

	var currentTalk *Talk

	http.HandleFunc("/tulip", IncomingTalkHandler)
	http.Handle("/", http.FileServer(http.Dir("webroot")))


	/* Start things */
	info(term, "Listening on 127.0.0.1:%s", localPort)
	go http.ListenAndServe(fmt.Sprintf(":%s", localPort), nil)

	go func(){
		for {
			connected := <-connectEvent
			alert(term, "%s has connected", connected)
		}
	}()

	for {
		updateTalkMap()

		promptPrefix := ""
		if currentTalk != nil {
			promptPrefix = currentTalk.GetBestName()
		}
		term.SetPrompt(fmt.Sprintf("%s > ", promptPrefix))

		input, err := term.ReadLine()
		if err != nil {
			critical(term, "Unable to read line from terminal: %v", err)
		}
		if strings.HasPrefix(input, "/") {
			cmdLine := strings.TrimPrefix(input, "/")
			args := strings.Split(cmdLine, " ")
			switch args[0] {
			case "lt": // List talks
				for _, talk := range activeTalks {
					info(term, "[*] %s", talk.GetBestName())
				}
			case "":
				found := false
				for _, talk := range activeTalks {
					if args[1] == talk.GetBestName() {
						currentTalk = talk
						found = true
						break
					}
				}
				if !found {
					warn(term, "No such talk")
				}
			case "addab": // Add entry to the address book
				if len(args) != 3 {
					warn(term, "This command needs 2 arguments")
					break
				}
				name := args[1]
				id := args[2]
				idType := "otr-fp"
				abEntry := AddressBookEntry{Value: id, Type: idType}
				if _, ok := addressBook[name]; !ok {
					addressBook[name] = Person{}
				}
				addressBook[name] = append(addressBook[name], abEntry)
			case "connect":
				if !strings.HasSuffix(args[1], ".onion") { //check existence!
					warn(term, "It's not an onion address.")
					break
				}
				onionAddress := args[1]
				go connectToOnion(torConfig, onionAddress)
			default:
				warn(term, "No such command.")
			}
			continue
		}
		if currentTalk != nil {
			currentTalk.outgoing <-input
		} else {
			warn(term, "There is no active talk.")
		}
	}
}
