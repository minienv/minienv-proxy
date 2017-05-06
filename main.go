package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <port>", os.Args[0])
	}
	if _, err := strconv.Atoi(os.Args[1]); err != nil {
		log.Fatalf("Invalid port: %s (%s)\n", os.Args[1], err)
	}
	err := http.ListenAndServe(":"+os.Args[1], NewReverseProxy(os.Getenv("DC_TARGET_HOST")))
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
