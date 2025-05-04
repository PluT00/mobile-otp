package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/PluT00/mobile-otp/configs"
	"github.com/PluT00/mobile-otp/internal/app/mobile/otp"
	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
	"github.com/PluT00/mobile-otp/internal/pkg/repositories"
	checkotp "github.com/PluT00/mobile-otp/internal/pkg/usecases/check_otp"
	createotp "github.com/PluT00/mobile-otp/internal/pkg/usecases/create_otp"
)

func main() {
	if err := godotenv.Load("configs/.env"); err != nil {
		log.Fatal("Error loading .env file")
	}

	if err := configs.InitConfig(); err != nil {
		log.Fatalf("Failed to init config: %v", err)
	}

	s := grpc.NewServer()
	redisClient := redis.NewClient(&redis.Options{
		Addr:     viper.GetString("redis.addr"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       viper.GetInt("redis.db"),
		Protocol: 2,
	})

	createOTPRepo := repositories.NewCreateOTPRepository(redisClient)
	checkOTPRepo := repositories.NewCheckOTPRepository(redisClient)

	createOTPUseCase := createotp.NewUseCase(createOTPRepo)
	checkOTPUseCase := checkotp.NewUseCase(checkOTPRepo)

	srv := otp.NewMobileOTP(
		createOTPUseCase,
		checkOTPUseCase,
	)

	desc.RegisterMobileOTPServer(s, srv)
	slog.Info("Registered MobileOTPServer")

	addr := fmt.Sprintf("%s:%s", viper.GetString("grpc_listen.host"), viper.GetString("grpc_listen.port"))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	slog.Info("Listening on " + addr)

	slog.Info("Started serving...")
	if err := s.Serve(l); err != nil {
		log.Fatalf("Error while serving: %v", err)
	}
}
