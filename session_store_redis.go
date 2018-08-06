package main

import (
	"log"
	"github.com/go-redis/redis"
	"encoding/json"
	"strconv"
)

type RedisSessionStore struct {
	Client *redis.Client
}

func NewRedisSessionStore(address string, password string, dbStr string) (*RedisSessionStore, error) {
	db, _ := strconv.ParseInt(dbStr, 10, 64)
	client := redis.NewClient(&redis.Options{
		Addr: address,
		Password: password,
		DB: int(db),
	})
	_, err := client.Ping().Result()
	if err != nil {
		log.Printf("Failed to ping Redis: %v\n", err)
		return nil, err
	}
	return &RedisSessionStore{
		Client: client,
	}, nil
}

func (store RedisSessionStore) getSession(id string) (*Session, error) {
	bs, err := store.Client.Get(id).Bytes()
	if err != nil {
		return nil, err
	}
	var session Session
	err = json.Unmarshal(bs, &session)
	if err != nil {
		log.Printf("Redis error getting session: %v\n", err)
		return nil, err
	}
	return &session, nil
}