package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
	"web-push/services"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

type Preferences struct {
	Ask         string `json:"Ask"`
	AskSelector string `json:"AskSelector"`
	AskEvent    string `json:"AskEvent"`
}

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

type UserPreferences struct {
	Title       string
	Body        string
	Icon        string
	ClickAction string
}

type NotificationAction struct {
	Action string `json:"action"`
	Title  string `json:"title"`
	Icon   string `json:"icon,omitempty"`
}

var userPreferences = UserPreferences{
	Title:       "Hello, Mehtab Gill!",
	Body:        "This is your custom notification.",
	Icon:        "/icons/user123.png",
	ClickAction: "/dashboard",
}

var (
	secret = []byte("my_secret_key")
	ctx    = context.Background()
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func main() {

	godotenv.Load()

	services.InitRedis()

	vapidPublicKey := os.Getenv("VAPID_PUBLIC_KEY")
	vapidPrivateKey := os.Getenv("VAPID_PRIVATE_KEY")

	defer services.CloseRedis()

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/preferences", preferencesHandler)

	http.HandleFunc("/service-worker.js", func(w http.ResponseWriter, r *http.Request) {
		// Generate dynamic service worker script
		swScript := fmt.Sprintf(`
self.addEventListener('push', function(event) {
    const data = event.data ? event.data.text() : 'No payload';
	const text  =  event.data.text();
	const info = JSON.parse(text)

    const options = {
        body: info.body,
        icon: '/icon.png', // Optional icon
        vibrate: [100, 50, 100],
        actions: info.actions
    };

    event.waitUntil(
        self.registration.showNotification(info.title || 
		"%s", options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();

    if (event.action === 'explore') {
        clients.openWindow('https://example.com'); // Change URL
    } else {
        console.log('Notification closed');
    }
});

`, userPreferences.Title)

		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(swScript))
	})

	http.HandleFunc("/info/", func(w http.ResponseWriter, r *http.Request) {
		userKey := r.URL.Path[len("/info/"):]
		prefs, err := services.Rdb.HGetAll(ctx, fmt.Sprintf("preferences:%s", userKey)).Result()
		if err != nil {
			http.Error(w, "Error fetching preferences", http.StatusInternalServerError)
			return
		}
		prefs["ApplicationServerKey"] = vapidPublicKey

		json.NewEncoder(w).Encode(prefs)
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

		err = services.Rdb.HSet(ctx, "subscriptions", req.UserID, subscriptionData).Err()
		if err != nil {
			http.Error(w, "Failed to store subscription in Redis", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Subscription received."))
	})

	http.HandleFunc("/unsubscribe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		// Decode the incoming request
		var req struct {
			UserID string `json:"userid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Check if the UserID exists in Redis
		exists, err := services.Rdb.HExists(ctx, "subscriptions", req.UserID).Result()
		if err != nil {
			http.Error(w, "Failed to query Redis", http.StatusInternalServerError)
			return
		}

		if !exists {
			http.Error(w, "User not found in subscriptions", http.StatusNotFound)
			return
		}

		// Remove the user subscription
		err = services.Rdb.HDel(ctx, "subscriptions", req.UserID).Err()
		if err != nil {
			http.Error(w, "Failed to remove subscription", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("User unsubscribed successfully."))
	})

	http.HandleFunc("/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		subscriptions, err := services.Rdb.HGetAll(ctx, "subscriptions").Result()
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

		var req struct {
			Title   string               `json:"Title"`
			Message string               `json:"message"`
			Actions []NotificationAction `json:"actions,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		subscriptions, err := services.Rdb.HGetAll(ctx, "subscriptions").Result()
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

			payload := map[string]interface{}{
				"title":   req.Title,
				"body":    req.Message,
				"actions": req.Actions,
			}

			payloadJSON, _ := json.Marshal(payload)

			go func(sub webpush.Subscription) {
				resp, err := webpush.SendNotification([]byte(payloadJSON), &sub, &webpush.Options{
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

	http.HandleFunc("/notify-user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			UserID  string               `json:"userid"`
			Message string               `json:"message"`
			Title   string               `json:"title"`
			Actions []NotificationAction `json:"actions,omitempty"`
		}

		// Decode the JSON request body
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Fetch the subscription data from Redis
		subData, err := services.Rdb.HGet(ctx, "subscriptions", req.UserID).Result()
		if err != nil {
			if err == redis.Nil {
				http.Error(w, "Subscription not found for the given user", http.StatusNotFound)
			} else {
				http.Error(w, "Failed to fetch subscription from Redis", http.StatusInternalServerError)
			}
			return
		}

		payload := map[string]interface{}{
			"title":   req.Title,
			"body":    req.Message,
			"actions": req.Actions,
		}
		payloadJSON, _ := json.Marshal(payload)

		// Parse the subscription data into a webpush.Subscription struct
		var subscription webpush.Subscription
		if err := json.Unmarshal([]byte(subData), &subscription); err != nil {
			http.Error(w, "Failed to parse subscription data", http.StatusInternalServerError)
			fmt.Printf("Failed to decode subscription: %v\n", err)
			return
		}

		// Send the notification in a goroutine
		go func(sub webpush.Subscription) {
			resp, err := webpush.SendNotification([]byte(payloadJSON), &sub, &webpush.Options{
				VAPIDPublicKey:  vapidPublicKey,
				VAPIDPrivateKey: vapidPrivateKey,
				TTL:             30,
				HTTPClient:      &http.Client{},
			})

			if err != nil {
				fmt.Printf("Failed to send notification: %v\n", err)
				return
			}
			defer resp.Body.Close()
			fmt.Println("Notification sent successfully!")
		}(subscription)

		// Send a success response
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("Notification sent to the user %s", req.UserID)))
	})

	fmt.Println("Server starting on http://localhost:8080")
	if err := http.ListenAndServe(":8080", cors.Default().Handler(http.DefaultServeMux)); err != nil {
		panic(err)
	}

}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	user.Password = string(passwordHash)
	key := fmt.Sprintf("user:%s", user.Username)

	if err := services.Rdb.HSet(ctx, key, map[string]interface{}{
		"username":      user.Username,
		"password_hash": user.Password,
		"email":         user.Email,
		"created_at":    time.Now().String(),
	}).Err(); err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("user:%s", user.Username)
	passwordHash, err := services.Rdb.HGet(ctx, key, "password_hash").Result()
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(user.Password)) != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	claims := &Claims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		http.Error(w, "Error creating token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

func preferencesHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	token, err := jwt.ParseWithClaims(tokenStr[len("Bearer "):], &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(*Claims)
	userKey := fmt.Sprintf("preferences:%s", claims.Username)

	if r.Method == http.MethodGet {
		fmt.Printf("Failed to decode subscription: %v\n", userKey)
		prefs, err := services.Rdb.HGetAll(ctx, userKey).Result()
		if err != nil {
			http.Error(w, "Error fetching preferences", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(prefs)
		return
	}

	if r.Method == http.MethodPut {
		var prefs Preferences
		if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if err := services.Rdb.HSet(ctx, userKey, map[string]interface{}{
			"Ask":         prefs.Ask,
			"AskSelector": prefs.AskSelector,
			"AskEvent":    prefs.AskEvent,
		}).Err(); err != nil {
			http.Error(w, "Error saving preferences", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Preferences updated successfully",
		})
	}
}
