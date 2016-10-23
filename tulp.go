package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/twstrike/otr3"
	"github.com/nogoegst/bulb"
	bulb_utils "github.com/nogoegst/bulb/utils"
	"github.com/nogoegst/onionutil"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/proxy"
)

var term *terminal.Terminal

func IncomingTalkHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		warn(term, "Unable to upgrade: %v", err)
		return
	}
	info(term, "Got new connection")
	talk := NewTalk(ws)
	// Collect messages to terminal
	go func(){
		for {
			inMsg := <-talk.incoming
			ToTerm <- fmt.Sprintf("%s: %s", talk.GetBestName(), inMsg)
		}
	}()
}


func main() {
	var debug_flag = flag.Bool("debug", false,
		"Show what's happening")
	var localFlag = flag.Bool("local", false,
		"Run locally (offline)")
	var control = flag.String("control-addr", "tcp://127.0.0.1:9051",
		"Set Tor control address to be used")
	var control_passwd = flag.String("control-passwd", "",
		"Set Tor control auth password")
	flag.Parse()
	debug := *debug_flag

	oldTermState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldTermState)

	term = terminal.NewTerminal(os.Stdin, "")


	term.SetBracketedPasteMode(true)
	defer term.SetBracketedPasteMode(false)

	info(term, "Welcome to tulip!")

	// Parse control string
	control_net, control_addr, err := bulb_utils.ParseControlPortString(*control)
	if err != nil {
		critical(term, "Failed to parse Tor control address string: %v", err)
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
	//privKey.Generate(rand.Reader)
	//log.Printf(base64.RawStdEncoding.EncodeToString(privKey.Serialize(nil)))
	info(term, "Our fingerprint: %x", privKey.Fingerprint())

	browserFP, _ := hex.DecodeString("2264d806e7789a5773bdaffb798bcf3fdb456a81")
	browserP := Person{OTRFingerprints: [][]byte{browserFP}}
	addressBook["browser"] = browserP
	info(term, "%v", addressBook)

	var currentTalk *Talk

	http.HandleFunc("/tulip", IncomingTalkHandler)
	http.Handle("/", http.FileServer(http.Dir("webroot")))

	freePort := GetPort()
	info(term, "gotPort: %d", freePort)
	go http.ListenAndServe(fmt.Sprintf(":%d", freePort), nil)

	if !(*localFlag) {
		// Connect to a running tor instance.
		c, err := bulb.Dial(control_net, control_addr)
		if err != nil {
			critical(term, "Failed to connect to control socket: %v", err)
		}
		defer c.Close()

		// See what's really going on under the hood.
		// Do not enable in production.
		c.Debug(debug)

		// Authenticate with the control port.  The password argument
		// here can be "" if no password is set (CookieAuth, no auth).
		if err := c.Authenticate(*control_passwd); err != nil {
			critical(term, "Authentication failed: %v", err)
		}

		// At this point, c.Request() can be used to issue requests.
		resp, err := c.Request("GETINFO version")
		if err != nil {
			critical(term, "GETINFO version failed: %v", err)
		}
		info(term, "We're using tor %v", resp.Data[0])

		c.StartAsyncReader()

		onionPassphrase, err := term.ReadPassword(fmt.Sprintf("Enter your passphrase for onion identity: "))
		if err != nil {
			critical(term, "Unable to read onion passphrase: %v", err)
		}

		privOnionKey, err := onionutil.GenerateOnionKey(onionutil.KeystreamReader([]byte(onionPassphrase), []byte("tulp-onion-keygen")))
		if err != nil {
			critical(term, "Unable to generate onion key: %v", err)
		}

		onionPortSpec := []bulb.OnionPortSpec{bulb.OnionPortSpec{80,
			strconv.FormatUint((uint64)(freePort), 10)}}
		onionInfo, err := c.AddOnion(onionPortSpec, privOnionKey, true)
		if err != nil {
			critical(term, "Error occured: %v", err)
		}
		info(term, "You're at %v.onion", onionInfo.OnionID)
	}

	/*
		showIncoming := func() {
			for {
			}
		}
		go showIncoming()
	*/
	go func() {
		for {
			info(term, <-ToTerm)
		}
	}()

	for {
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
			case "list":
				for _, talk := range activeTalks {
					info(term, "[*] %s", talk.GetBestName())
				}
			case "":
				if talk, ok := activeTalks[args[1]]; ok {
					currentTalk = talk
				} else {
					warn(term, "No such talk")
				}
			case "connect":
				if !strings.HasSuffix(args[1], ".onion") { //check existence!
					warn(term, "It's not an onion address.")
					break
				}
				onionAddress := args[1]
				url := "ws://" + onionAddress + "/tulip"
				torDialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
				if err != nil {
					alert(term, "Unable to create a tor dialer: %v", err)
					break
				}
				dialer := websocket.Dialer{NetDial: torDialer.Dial}
				requestHeader := make(http.Header)
				ws, _, err := dialer.Dial(url, requestHeader)
				if err != nil {
					alert(term, "Unable to connect")
					break
				}
				_ = NewTalk(ws)
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
