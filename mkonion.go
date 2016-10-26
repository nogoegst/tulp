package main

import(
	"fmt"

	"golang.org/x/net/proxy"
	"github.com/nogoegst/onionutil"
	"github.com/nogoegst/bulb"
)

type TorConfig struct {
	SocksAddr	string
	Control		string
	ControlPassword	string
	Debug		bool
}

// XXX: Rewrite to use Dialer from bulb
func (tc TorConfig) GetTorDialer() (proxy.Dialer, error) {
	return proxy.SOCKS5("tcp", tc.SocksAddr, nil, proxy.Direct)
}

func (tc TorConfig) MakeOnion(localPort string) (onion string, err error) {
	// Connect to a running tor instance.
	c, err := bulb.DialURL(tc.Control)
	if err != nil {
		err = fmt.Errorf("Failed to connect to control socket: %v", err)
		return
	}

	// See what's really going on under the hood.
	// Do not enable in production.
	c.Debug(tc.Debug)

	// Authenticate with the control port.  The password argument
	// here can be "" if no password is set (CookieAuth, no auth).
	if err = c.Authenticate(tc.ControlPassword); err != nil {
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
