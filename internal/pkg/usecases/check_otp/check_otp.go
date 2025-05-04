package checkotp

import (
	"context"

	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
)

type (
	CheckOTPRepository interface {
		GetOTP(ctx context.Context, userId string) string
	}

	UseCase struct {
		repository CheckOTPRepository
	}
)

func NewUseCase(repository CheckOTPRepository) *UseCase {
	return &UseCase{
		repository: repository,
	}
}

func (uc *UseCase) CheckOTP(ctx context.Context, req *desc.CheckOTPRequest) (*desc.CheckOTPResponse, error) {
	otp := uc.repository.GetOTP(ctx, req.GetId())

	if otp != req.GetOtp().GetCode() {
		return &desc.CheckOTPResponse{
			Ok: false,
		}, nil
	}

	return &desc.CheckOTPResponse{
		Ok: true,
	}, nil
}
