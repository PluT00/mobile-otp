package otp

import (
	"context"

	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
)

type (
	NeedOTPUseCase interface {
		NeedOTP(ctx context.Context, req *desc.NeedOTPRequest) (*desc.NeedOTPResponse, error)
	}

	ValidateOTPUseCase interface {
		ValidateOTP(ctx context.Context, req *desc.ValidateOTPRequest) (*desc.ValidateOTPResponse, error)
	}

	GetOTPUseCase interface {
		GetOTP(ctx context.Context, req *desc.GetOTPRequest) (*desc.GetOTPResponse, error)
	}

	Implementation struct {
		desc.UnimplementedMobileOTPServer

		needOTP     NeedOTPUseCase
		validateOTP ValidateOTPUseCase
		getOTP      GetOTPUseCase
	}
)

func NewMobileOTP(
	needOTPUseCase NeedOTPUseCase,
	validateOTPUseCase ValidateOTPUseCase,
	getOTP GetOTPUseCase,
) *Implementation {
	return &Implementation{
		needOTP:     needOTPUseCase,
		validateOTP: validateOTPUseCase,
		getOTP:      getOTP,
	}
}
