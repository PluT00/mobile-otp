package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/PluT00/mobile-otp/internal/pkg/usecases/sync_keys"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/PluT00/mobile-otp/configs"
	"github.com/PluT00/mobile-otp/internal/app/mobile/otp"
	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
	"github.com/PluT00/mobile-otp/internal/pkg/repositories"
	"github.com/PluT00/mobile-otp/internal/pkg/usecases/get_otp"
	"github.com/PluT00/mobile-otp/internal/pkg/usecases/need_otp"
	"github.com/PluT00/mobile-otp/internal/pkg/usecases/validate_otp"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

func main() {
	// Load .env file
	if err := godotenv.Load("configs/.env"); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize configuration
	if err := configs.InitConfig(); err != nil {
		log.Fatalf("Failed to init config: %v", err)
	}

	logger := setupLogger()
	entry := logrus.NewEntry(logger)

	// Setup gRPC server (insecure)
	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_logrus.UnaryServerInterceptor(entry)),
		grpc.StreamInterceptor(grpc_logrus.StreamServerInterceptor(entry)),
	)
	redisClient := redis.NewClient(&redis.Options{
		Addr:     viper.GetString("redis.addr"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       viper.GetInt("redis.db"),
		Protocol: 2,
	})

	// Initialize repositories and use cases
	needOTPRepo := repositories.NewNeedOTPRepository(redisClient)
	validateOTPRepo := repositories.NewValidateOTPRepository(redisClient)
	getOTPRepo := repositories.NewGetOTPRepository(redisClient)
	syncKeysRepo := repositories.NewSyncKeysRepository(redisClient)

	needOTPUseCase := need_otp.NewUseCase(needOTPRepo)
	validateOTPUseCase := validate_otp.NewUseCase(validateOTPRepo)
	getOTPUseCase := get_otp.NewUseCase(getOTPRepo)
	syncKeysUseCase := sync_keys.NewUseCase(syncKeysRepo)

	// Create MobileOTP service
	srv := otp.NewMobileOTP(needOTPUseCase, validateOTPUseCase, getOTPUseCase, syncKeysUseCase)
	desc.RegisterMobileOTPServer(s, srv)
	slog.Info("Registered MobileOTPServer")

	// gRPC server address
	grpcAddr := fmt.Sprintf("%s:%s", viper.GetString("grpc_listen.host"), viper.GetString("grpc_listen.port"))
	grpcListener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("Failed to create gRPC listener: %v", err)
	}
	slog.Info("gRPC server listening on " + grpcAddr)

	// Setup HTTP server with gRPC-Gateway
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create gRPC-Gateway mux
	gwMux := runtime.NewServeMux()

	// Connect to gRPC server (insecure) using grpc.NewClient
	grpcConn, err := grpc.NewClient(
		grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer grpcConn.Close()

	// Register gRPC-Gateway handler
	err = desc.RegisterMobileOTPHandler(ctx, gwMux, grpcConn)
	if err != nil {
		log.Fatalf("Failed to register gRPC-Gateway handler: %v", err)
	}

	// Create HTTP router
	httpRouter := chi.NewRouter()
	httpRouter.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
	}))

	httpRouter.Mount("/", gwMux)

	// Serve Swagger JSON
	swaggerPath := viper.GetString("swagger.gw_swagger_json")
	httpRouter.Get("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Serving Swagger JSON: " + swaggerPath)
		http.ServeFile(w, r, swaggerPath)
	})

	// HTTP server address
	httpAddr := fmt.Sprintf("%s:%s", viper.GetString("http_listen.host"), viper.GetString("http_listen.port"))
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: httpRouter,
	}

	// Start servers in goroutines
	go func() {
		slog.Info("HTTP server listening on " + httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to serve HTTP: %v", err)
		}
	}()

	go func() {
		slog.Info("Started serving gRPC...")
		if err := s.Serve(grpcListener); err != nil {
			log.Fatalf("Error while serving gRPC: %v", err)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	slog.Info("Shutting down...")

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server shutdown error: " + err.Error())
	}

	// Stop gRPC server
	s.GracefulStop()
	slog.Info("Shutdown complete")
}

func setupLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{}) // Example: JSON format
	logger.SetLevel(logrus.DebugLevel)           // Example: Debug level
	return logger
}
