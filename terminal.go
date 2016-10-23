package main

import (
	"os"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)
// appendTerminalEscaped acts like append(), but breaks terminal escape
// sequences that may be in msg.
func appendTerminalEscaped(out, msg []byte) []byte {
	for _, c := range msg {
		if c == 127 || (c < 32 && c != '\t') {
			out = append(out, '?')
		} else {
			out = append(out, c)
		}
	}
	return out
}


func terminalMessage(term *terminal.Terminal, color []byte, msg string, critical bool) {
	line := make([]byte, 0, len(msg)+16)

	line = append(line, ' ')
	line = append(line, color...)
	line = append(line, '*')
	line = append(line, term.Escape.Reset...)
	line = append(line, []byte(fmt.Sprintf(" (%s) ", time.Now().Format(time.Kitchen)))...)
	if critical {
		line = append(line, term.Escape.Red...)
	}
	line = appendTerminalEscaped(line, []byte(msg))
	if critical {
		line = append(line, term.Escape.Reset...)
	}
	line = append(line, []byte("\n\r")...)
	term.Write(line)

	if critical {
		os.Exit(1)
	}
}

func info(term *terminal.Terminal, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	terminalMessage(term, term.Escape.Blue, msg, false)
}
func warn(term *terminal.Terminal, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	terminalMessage(term, term.Escape.Magenta, msg, false)
}
func alert(term *terminal.Terminal, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	terminalMessage(term, term.Escape.Red, msg, false)
}
func critical(term *terminal.Terminal, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	terminalMessage(term, term.Escape.Red, msg, true)
}
