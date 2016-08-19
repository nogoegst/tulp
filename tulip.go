package main

import (
	"log"
	"fmt"
	"net/http"
	"crypto/sha256"
	"golang.org/x/net/websocket"
)

func echoHandler(ws *websocket.Conn) {
	for {
		data := make([]byte, 512)
		n, err := ws.Read(data)
		if err != nil {
			log.Printf("Unable to read data: %v", err)
			break
		}
		log.Printf("%s", data[:n])

		sha_256 := sha256.New()
		sha_256.Write(data[:n])
		hashString := fmt.Sprintf("sha256: %x", sha_256.Sum(nil))

		_, err = ws.Write([]byte(hashString))
		if err != nil {
			log.Printf("Unable to read data: %v", err)
			break
		}
	}
	defer ws.Close()
}


func main() {
	log.Printf("Welcome to tulip!")
	http.Handle("/tulip", websocket.Handler(echoHandler))
	http.Handle("/", http.FileServer(http.Dir("webroot")))

	log.Fatal(http.ListenAndServe(":8000", nil))
}
