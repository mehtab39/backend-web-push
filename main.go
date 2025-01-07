package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

type SubscriptionRequest struct {
	Subscription webpush.Subscription `json:"subscription"`
	UserID       string               `json:"userID"`
}

type SubscriptionItem struct {
	UserID       string               `json:"userID"`
	Subscription webpush.Subscription `json:"subscription"`
}

type Configuration struct {
	ApplicationServerKey string `json:"applicationServerKey"`
	Ask                  string `json:"ask"`
	AskSelector          string `json:"askSelector,omitempty"`
	AskEvent             string `json:"askEvent,omitempty"`
}

var redisClient *redis.Client
var ctx = context.Background()

func main() {

	godotenv.Load()

	vapidPublicKey := os.Getenv("VAPID_PUBLIC_KEY")
	vapidPrivateKey := os.Getenv("VAPID_PRIVATE_KEY")

	redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	defer redisClient.Close()

	http.Handle("/service-worker.js", http.FileServer(http.Dir("./resources/")))

	http.HandleFunc("/info/", func(w http.ResponseWriter, r *http.Request) {
		//webPushKey := r.URL.Path[len("/info/"):]
		config := Configuration{
			ApplicationServerKey: vapidPublicKey,
			Ask:                  "soft",
			AskSelector:          "#subscribe-button",
			AskEvent:             "click",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(config); err != nil {
			http.Error(w, "Failed to encode configuration", http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/subscribe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		var req SubscriptionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid subscription data", http.StatusBadRequest)
			return
		}

		subscriptionData, err := json.Marshal(req.Subscription)
		if err != nil {
			http.Error(w, "Failed to serialize subscription", http.StatusInternalServerError)
			return
		}

		err = redisClient.HSet(ctx, "subscriptions", req.UserID, subscriptionData).Err()
		if err != nil {
			http.Error(w, "Failed to store subscription in Redis", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Subscription received."))
	})

	http.HandleFunc("/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		subscriptions, err := redisClient.HGetAll(ctx, "subscriptions").Result()
		if err != nil {
			http.Error(w, "Failed to fetch subscriptions from Redis", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(subscriptions); err != nil {
			http.Error(w, "Failed to encode subscriptions", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/notify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		subscriptions, err := redisClient.HGetAll(ctx, "subscriptions").Result()
		if err != nil {
			http.Error(w, "Failed to fetch subscriptions from Redis", http.StatusInternalServerError)
			return
		}

		for _, subData := range subscriptions {
			var subscription webpush.Subscription
			if err := json.Unmarshal([]byte(subData), &subscription); err != nil {
				fmt.Printf("Failed to decode subscription: %v\n", err)
				continue
			}

			go func(sub webpush.Subscription) {
				resp, err := webpush.SendNotification([]byte("Hello! This is a broadcast notification."), &sub, &webpush.Options{
					VAPIDPublicKey:  vapidPublicKey,
					VAPIDPrivateKey: vapidPrivateKey,
					TTL:             30,
				})
				if err != nil {
					fmt.Printf("Failed to send notification: %v\n", err)
					return
				}
				defer resp.Body.Close()
				fmt.Println("Notification sent successfully!")
			}(subscription)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Notifications sent to all subscriptions."))
	})

	fmt.Println("Server starting on http://localhost:8080")
	if err := http.ListenAndServe(":8080", cors.Default().Handler(http.DefaultServeMux)); err != nil {
		panic(err)
	}
}
