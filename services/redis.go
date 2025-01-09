package services

import (
	"context"
	"fmt"
	"log"

	"github.com/go-redis/redis/v8"
)

var Rdb *redis.Client
var ctx = context.Background()

func InitRedis() {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	_, err := Rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	fmt.Println("Connected to Redis successfully")
}

func CloseRedis() {
	err := Rdb.Close()
	if err != nil {
		log.Fatalf("Error closing Redis: %v", err)
	}
	fmt.Println("Redis connection closed")
}
