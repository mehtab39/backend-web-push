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

    const options = {
        body: data,
        icon: '/icon.png', // Optional icon
        vibrate: [100, 50, 100],
        actions: [
            { action: 'explore', title: 'Explore this', icon: '/check.png' },
            { action: 'close', title: 'Close', icon: '/close.png' }
        ]
    };

    event.waitUntil(
        self.registration.showNotification('%s', options)
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
