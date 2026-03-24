package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-system/internal/config"
	"auth-system/internal/delivery/http/handler"
	"auth-system/internal/delivery/http/middleware"
	"auth-system/internal/domain"
	"auth-system/internal/infrastructure/cache"
	"auth-system/internal/infrastructure/db"
	"auth-system/internal/infrastructure/oauth"
	"auth-system/internal/repository"
	"auth-system/internal/usecase"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// ---------- 1. Config ----------
	cfg := config.LoadConfig()

	// ---------- 2. Infrastructure ----------
	mongoClient := db.NewMongoClient(cfg.MongoURI)
	mongoDB := mongoClient.Database(cfg.DBName)

	redisClient := cache.NewRedisClient(cache.RedisConfig{
		URI:      cfg.RedisURI,
		Password: cfg.RedisPassword,
	})

	googleOAuth := oauth.NewGoogleOAuth(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL)
	githubOAuth := oauth.NewGithubOAuth(cfg.GithubClientID, cfg.GithubClientSecret, cfg.GithubRedirectURL)

	// ---------- 3. Repositories ----------
	userRepo := repository.NewUserRepository(mongoDB)
	sessionRepo := repository.NewSessionRepository(redisClient)

	// ---------- 4. Usecases ----------
	authUC := usecase.NewAuthUsecase(userRepo, sessionRepo, googleOAuth, githubOAuth, cfg.JWTSecret)
	userUC := usecase.NewUserUsecase(userRepo)

	// ---------- 5. Handlers ----------
	authHandler := handler.NewAuthHandler(authUC, cfg)
	userHandler := handler.NewUserHandler(userUC)

	// ---------- 6. Router ----------
	router := setupRouter(cfg, redisClient, authHandler, userHandler)

	// ---------- 7. Server with graceful shutdown ----------
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,  // time to read headers (slowloris protection)
		ReadTimeout:       10 * time.Second, // total read timeout
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB max header size
	}

	go func() {
		log.Printf("Server starting on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal (Ctrl+C, SIGTERM).
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Give active requests 5 seconds to finish.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	redisClient.Close()
	mongoClient.Disconnect(ctx)
	log.Println("Server exited cleanly")
}

func setupRouter(
	cfg *config.Config,
	redisClient *cache.RedisClient,
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
) *gin.Engine {
	router := gin.Default()

	// ---------- Global Middleware (order matters) ----------

	// 1. Request ID — attach a trace ID to every request.
	router.Use(middleware.RequestID())

	// 2. Security headers — harden every response.
	router.Use(middleware.SecurityHeaders())

	// 3. Body size limit — reject payloads over 1 MB.
	router.Use(middleware.BodyLimit(1 << 20))

	// 4. CORS — allow the frontend origin with credentials.
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.FrontendURL},
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization", "X-CSRF-Token", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 5. Global rate limiter — 100 req/min per IP.
	router.Use(middleware.RateLimiter(redisClient, middleware.RateLimitConfig{
		Window:      1 * time.Minute,
		MaxRequests: 100,
	}))

	// 6. CSRF — double-submit cookie protection on state-changing requests.
	router.Use(middleware.CSRF(cfg))

	// ---------- Trusted Proxies ----------
	// If behind a reverse proxy (nginx, cloudflare), set trusted proxies explicitly.
	// router.SetTrustedProxies([]string{"10.0.0.0/8"})

	// ---------- Health Check (no auth, no CSRF) ----------
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// ---------- API v1 ----------
	v1 := router.Group("/api/v1")

	// Auth routes (public) — stricter rate limit on login/register.
	auth := v1.Group("/auth")
	authLimiter := middleware.RateLimiter(redisClient, middleware.RateLimitConfig{
		Window:      1 * time.Minute,
		MaxRequests: 10, // 10 attempts/min — slows brute-force attacks
	})
	{
		auth.POST("/register", authLimiter, authHandler.Register)
		auth.POST("/login", authLimiter, authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)

		// OAuth — GET requests, CSRF is handled by the oauth_state cookie.
		auth.GET("/google", authHandler.GoogleLogin)
		auth.GET("/google/callback", authHandler.GoogleCallback)
		auth.GET("/github", authHandler.GithubLogin)
		auth.GET("/github/callback", authHandler.GithubCallback)
	}

	// User routes (authenticated).
	users := v1.Group("/users")
	users.Use(middleware.Auth(cfg.JWTSecret))
	{
		users.GET("/me", userHandler.GetProfile)
		users.PATCH("/me", userHandler.UpdateProfile)

		// Admin-only.
		users.GET("", middleware.RequireRole(domain.RoleAdmin), userHandler.ListUsers)
		users.DELETE("/:id", middleware.RequireRole(domain.RoleAdmin), userHandler.DeleteUser)
	}

	return router
}
