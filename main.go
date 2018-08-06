package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
)

var sessionStore SessionStore

type SessionStore interface {
	getSession(id string) (*Session, error)
}

type Session struct {
	Id string  `json:"sessionId"`
	EnvId string `json:"envId"`
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <port>", os.Args[0])
	}
	if _, err := strconv.Atoi(os.Args[1]); err != nil {
		log.Fatalf("Invalid port: %s (%s)\n", os.Args[1], err)
	}
	// load session store if specified
	redisAddress := os.Getenv("MINIENV_REDIS_ADDRESS")
	redisPassword := os.Getenv("MINIENV_REDIS_PASSWORD")
	redisDb := os.Getenv("MINIENV_REDIS_DB")
	if redisAddress != "" {
		redisSessionStore, err := NewRedisSessionStore(redisAddress, redisPassword, redisDb)
		if err != nil {
			sessionStore = nil
		} else {
			sessionStore = redisSessionStore
		}
	}
	// start listening
	err := http.ListenAndServe(":"+os.Args[1], NewReverseProxy(os.Getenv("MINIENV_TARGET_HOST")))
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
