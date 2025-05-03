package otp

import (
	"context"
	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
)

type (
	CreateOTPUseCase interface {
		CreateOTP(ctx context.Context, req *desc.CreateOTPRequest) (*desc.CreateOTPResponse, error)
	}

	CheckOTPUseCase interface {
		CheckOTP(ctx context.Context, req *desc.CheckOTPRequest) (*desc.CheckOTPResponse, error)
	}

	Implementation struct {
		desc.UnimplementedMobileOTPServer

		createOTP CreateOTPUseCase
		checkOTP  CheckOTPUseCase
	}
)

func NewMobileOTP() *Implementation {
	return &Implementation{}
}
