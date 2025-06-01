package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	PostgresDSN string
	JWTSecret   string
	Port        string
}

type App struct {
	DB     *sql.DB
	Config *Config
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type VerifyJWTRequest struct {
	JWT string `json:"jwt"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type VerifyJWTResponse struct {
	Valid  bool   `json:"valid"`
	UserID string `json:"user_id"`
}

func main() {
	config := &Config{
		PostgresDSN: "host=postgres port=5432 user=authuser password=authpass dbname=authuser sslmode=disable", // Place in .env file
		JWTSecret:   "your_jwt_secret_key_1234567890",                                                          // Replace with secure key
		Port:        ":8081",
	}

	// Override with environment variables
	if dsn := os.Getenv("POSTGRES_DSN"); dsn != "" {
		config.PostgresDSN = dsn
	}
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		config.JWTSecret = secret
	}
	if port := os.Getenv("PORT"); port != "" {
		config.Port = ":" + port
	}

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", config.PostgresDSN)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Initialize schema
	if err := initSchema(db); err != nil {
		log.Fatalf("Failed to initialize schema: %v", err)
	}

	app := &App{DB: db, Config: config}

	// Set up router
	r := chi.NewRouter()
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // Adjust for production
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
	}))

	r.Post("/register", app.handleRegister)
	r.Post("/login", app.handleLogin)
	r.Post("/verify-jwt", app.handleVerifyJWT)

	// Start server
	log.Printf("Server starting on %s", config.Port)
	if err := http.ListenAndServe(config.Port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func initSchema(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS users (
			id uuid PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`
	_, err := db.Exec(query)
	return err
}

func (app *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	// Validate input
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	if req.Username == "" || req.Password == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Username and password are required"})
		return
	}
	if len(req.Username) < 3 || len(req.Password) < 6 {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Username must be at least 3 characters, password at least 6"})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to process password"})
		return
	}
	userId := uuid.Must(uuid.NewV7())

	// Insert user
	_, err = app.DB.ExecContext(r.Context(),
		"INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)",
		userId, req.Username, string(hash))
	if err != nil {
		if strings.Contains(err.Error(), "unique constraint") {
			respondJSON(w, http.StatusConflict, map[string]string{"error": "Username already exists"})
		} else {
			log.Printf("Register error: %v", err)
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to register"})
		}
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{})
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	// Validate input
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	if req.Username == "" || req.Password == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Username and password are required"})
		return
	}

	// Query user
	var userID uuid.UUID
	var passwordHash string
	err := app.DB.QueryRowContext(r.Context(),
		"SELECT id, password_hash FROM users WHERE username = $1", req.Username).
		Scan(&userID, &passwordHash)
	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	} else if err != nil {
		log.Printf("Login query error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	// Generate JWT
	token, err := generateJWT(userID.String(), app.Config.JWTSecret)
	if err != nil {
		log.Printf("JWT generation error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
		return
	}

	respondJSON(w, http.StatusOK, LoginResponse{Token: token})
}

func (app *App) handleVerifyJWT(w http.ResponseWriter, r *http.Request) {
	var req VerifyJWTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	// Validate Bearer prefix
	if !strings.HasPrefix(req.JWT, "Bearer ") {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "JWT must start with 'Bearer '"})
		return
	}
	tokenString := strings.TrimPrefix(req.JWT, "Bearer ")
	log.Printf("Received JWT: %s", tokenString)

	// Parse JWT with strict validation
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(app.Config.JWTSecret), nil
	})

	if err != nil {
		log.Printf("JWT parsing error: %v", err)
		respondJSON(w, http.StatusOK, VerifyJWTResponse{Valid: false, UserID: ""})
		return
	}

	// Validate claims
	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok || !token.Valid {
		log.Printf("Invalid JWT: valid=%v, claims type=%T", token.Valid, token.Claims)
		respondJSON(w, http.StatusOK, VerifyJWTResponse{Valid: false, UserID: ""})
		return
	}

	// Extract user_id
	var userID string
	switch v := (*claims)["user_id"].(type) {
	case string:
		userID = v
	default:
		log.Printf("Invalid user_id type: %T, value: %v", (*claims)["user_id"], (*claims)["user_id"])
		respondJSON(w, http.StatusOK, VerifyJWTResponse{Valid: false, UserID: ""})
		return
	}

	// Verify expiration
	if exp, ok := (*claims)["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			log.Printf("JWT expired: exp=%v", exp)
			respondJSON(w, http.StatusOK, VerifyJWTResponse{Valid: false, UserID: ""})
			return
		}
	} else {
		log.Printf("Missing or invalid exp claim")
		respondJSON(w, http.StatusOK, VerifyJWTResponse{Valid: false, UserID: ""})
		return
	}

	log.Printf("JWT verified successfully, user_id: %d", userID)
	respondJSON(w, http.StatusOK, VerifyJWTResponse{Valid: true, UserID: userID})
}

func generateJWT(userID, secret string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
