package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	Port        string
	FrontendURL string // for CORS and OAuth redirects

	// Database
	MongoURI string
	DBName   string

	// Redis (Upstash — use the rediss:// protocol URL, not the REST URL)
	RedisURI      string
	RedisPassword string

	// JWT
	JWTSecret string

	// OAuth — Google
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	// OAuth — GitHub
	GithubClientID     string
	GithubClientSecret string
	GithubRedirectURL  string

	// Cookie
	CookieDomain string
	CookieSecure bool
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from environment")
	}

	return &Config{
		Port:        getEnv("PORT", "8080"),
		FrontendURL: getEnv("FRONTEND_URL", "http://localhost:3000"),

		MongoURI: getEnv("MONGO_URI", ""),
		DBName:   getEnv("DB_NAME", "auth_system"),

		RedisURI:      getEnv("REDIS_URI", ""),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),

		JWTSecret: getEnv("JWT_SECRET", ""),

		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/api/v1/auth/google/callback"),

		GithubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		GithubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		GithubRedirectURL:  getEnv("GITHUB_REDIRECT_URL", "http://localhost:8080/api/v1/auth/github/callback"),

		CookieDomain: getEnv("COOKIE_DOMAIN", "localhost"),
		CookieSecure: getEnv("COOKIE_SECURE", "false") == "true",
	}
}

func getEnv(key string, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
