package main

import (
	"log"
	"net/http"
)

func main() {
	log.Printf("Welcome to tulip!")
	http.Handle("/", http.FileServer(http.Dir("webroot")))
	log.Fatal(http.ListenAndServe(":8000", nil))
}
