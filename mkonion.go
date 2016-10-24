package main

import(
	"fmt"

	"github.com/nogoegst/onionutil"
	"github.com/nogoegst/bulb"
	bulbUtils "github.com/nogoegst/bulb/utils"
)

func MakeOnion(control, controlPassword, localPort string, debug bool) (onion string, err error) {
	// Parse control string
	controlNet, controlAddr, err := bulbUtils.ParseControlPortString(control)
	if err != nil {
		err = fmt.Errorf("Failed to parse Tor control address string: %v", err)
	return
	}

	// Connect to a running tor instance.
	c, err := bulb.Dial(controlNet, controlAddr)
	if err != nil {
		err = fmt.Errorf("Failed to connect to control socket: %v", err)
		return
	}

	// See what's really going on under the hood.
	// Do not enable in production.
	c.Debug(debug)

	// Authenticate with the control port.  The password argument
	// here can be "" if no password is set (CookieAuth, no auth).
	if err = c.Authenticate(controlPassword); err != nil {
		err = fmt.Errorf("Authentication failed: %v", err)
		return
	}

	c.StartAsyncReader()

	onionPassphrase, err := term.ReadPassword(fmt.Sprintf("Enter your passphrase for onion identity: "))
	if err != nil {
		critical(term, "Unable to read onion passphrase: %v", err)
	}

	privOnionKey, err := onionutil.GenerateOnionKey(onionutil.KeystreamReader([]byte(onionPassphrase), []byte("tulp-onion-keygen")))
	if err != nil {
		critical(term, "Unable to generate onion key: %v", err)
	}
	onionPortSpec := []bulb.OnionPortSpec{bulb.OnionPortSpec{80, localPort}}
	onionInfo, err := c.AddOnion(onionPortSpec, privOnionKey, true)
	if err != nil {
		critical(term, "Error occured: %v", err)
	}
	return onionInfo.OnionID, nil
}
