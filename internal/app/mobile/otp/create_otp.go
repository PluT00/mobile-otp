package otp

import (
	"context"
	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
)

func (i *Implementation) CreateOTP(ctx context.Context, req *desc.CreateOTPRequest) (*desc.CreateOTPResponse, error) {
	return &desc.CreateOTPResponse{}, nil
}
