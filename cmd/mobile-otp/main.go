package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
	"log/slog"
	"net"

	"github.com/PluT00/mobile-otp/configs"
	"github.com/PluT00/mobile-otp/internal/app/mobile/otp"
	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
	"google.golang.org/grpc"
)

func main() {
	if err := configs.InitConfig(); err != nil {
		log.Fatalf("Failed to init config: %v", err)
	}

	s := grpc.NewServer()
	srv := otp.NewMobileOTP()
	desc.RegisterMobileOTPServer(s, srv)
	slog.Info("Registered MobileOTPServer")

	addr := fmt.Sprintf("%s:%s", viper.GetString("listen.host"), viper.GetString("listen.port"))
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
