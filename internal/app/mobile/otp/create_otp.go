package otp

import (
	"context"
	"time"

	"github.com/spf13/viper"

	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
)

func (i *Implementation) CreateOTP(ctx context.Context, req *desc.CreateOTPRequest) (*desc.CreateOTPResponse, error) {
	timeout := viper.GetDuration("grpc_listen.req_timeout_sec")
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Second*timeout)
	defer cancel()

	return i.createOTP.CreateOTP(ctxTimeout, req)
}
