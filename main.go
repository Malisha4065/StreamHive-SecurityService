package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
	"golang.org/x/crypto/bcrypt"
)

// --- CONFIGURATION ---
// Config holds all the configuration for the application, loaded from environment variables.
type Config struct {
	Port        string
	DBUrl       string
	JwtSecret   string
}

// loadConfig loads configuration from environment variables.
func loadConfig() Config {
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080" // Default port
	}

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbUrl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPass, dbHost, dbPort, dbName)

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	return Config{
		Port:      port,
		DBUrl:     dbUrl,
		JwtSecret: jwtSecret,
	}
}

// --- DATABASE & MODELS ---
// User represents the user model in the database.
type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"` // Omit password hash from JSON responses
	Role         string `json:"role"`
}

// Store handles all database operations.
type Store struct {
	db *sql.DB
}

// NewStore creates a new Store and ensures the users table exists.
func NewStore(dbUrl string) (*Store, error) {
	db, err := sql.Open("pgx", dbUrl)
	if err != nil {
		return nil, fmt.Errorf("could not open db connection: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("could not ping db: %w", err)
	}

	// Create the users table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("could not create users table: %w", err)
	}

	return &Store{db: db}, nil
}

// GetUserByEmail finds a user by their email address.
func (s *Store) GetUserByEmail(email string) (*User, error) {
	user := &User{}
	err := s.db.QueryRow("SELECT id, email, password_hash, role FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return user, nil
}

// CreateUser creates a new user in the database after hashing their password.
func (s *Store) CreateUser(email, password, role string) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &User{Email: email, Role: role}
	err = s.db.QueryRow(
		"INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
		email, string(hashedPassword), role,
	).Scan(&user.ID)
	if err != nil {
		// Handle potential unique constraint violation for email
		if strings.Contains(err.Error(), "unique constraint") {
			return nil, errors.New("email already in use")
		}
		return nil, err
	}

	return user, nil
}

// --- JWT & AUTH HELPERS ---
// generateJWT creates a new JWT for a given user.
func generateJWT(user *User, secret string) (string, error) {
	claims := jwt.MapClaims{
	"sub":  user.Email,
	"uid":  user.ID, // include user id to enable downstream authZ
	"role": user.Role,
	"exp":  time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	"iat":  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// --- API HANDLERS ---
// Handler holds dependencies for the API handlers.
type Handler struct {
	store *Store
	config Config
}

// SignupRequest defines the expected JSON body for the signup endpoint.
type SignupRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role"`
}

// signupHandler handles user registration.
func (h *Handler) signupHandler(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Default role to "USER" if not provided
	role := req.Role
	if role == "" {
		role = "USER"
	}

	user, err := h.store.CreateUser(req.Email, req.Password, role)
	if err != nil {
		// Check if it's a specific "email already in use" error
		if err.Error() == "email already in use" {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully", "userId": user.ID})
}

// LoginRequest defines the expected JSON body for the login endpoint.
type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// loginHandler handles user login.
func (h *Handler) loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := generateJWT(user, h.config.JwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":   user.ID,
			"email": user.Email,
			"role": user.Role,
		},
	})
}

// validateHandler is the endpoint used by other services to validate a token.
func (h *Handler) validateHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		c.Abort()
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token format required"})
		c.Abort()
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.config.JwtSecret), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
		return
	}

	email := claims["sub"].(string)
	user, err := h.store.GetUserByEmail(email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User in token not found"})
		c.Abort()
		return
	}
	
	// The Upload Service expects a specific structure
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id": user.ID,
			"email": user.Email,
			"permissions": []string{user.Role, "upload", "view"}, // Send back permissions
		},
	})
}

// --- MAIN FUNCTION ---
func main() {
	config := loadConfig()

	store, err := NewStore(config.DBUrl)
	if err != nil {
		log.Fatalf("Failed to initialize database store: %v", err)
	}
	
	handler := &Handler{
		store: store,
		config: config,
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Health check endpoint for Kubernetes probes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})

	// API routes
	api := router.Group("/api/auth")
	{
		api.POST("/signup", handler.signupHandler)
		api.POST("/login", handler.loginHandler)
		api.POST("/validate", handler.validateHandler) // Internal validation endpoint
	}

	log.Printf("Starting server on port %s", config.Port)
	if err := router.Run(":" + config.Port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}