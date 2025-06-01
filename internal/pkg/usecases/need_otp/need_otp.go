package need_otp

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
)

type (
	NeedOTPRepository interface {
		NeedOTP(ctx context.Context, userId string) error
	}

	UseCase struct {
		repository NeedOTPRepository
	}
)

func NewUseCase(repository NeedOTPRepository) *UseCase {
	return &UseCase{
		repository: repository,
	}
}

func (uc *UseCase) NeedOTP(ctx context.Context, req *desc.NeedOTPRequest) (*desc.NeedOTPResponse, error) {
	err := uc.repository.NeedOTP(ctx, req.GetId())
	if err != nil {
		return &desc.NeedOTPResponse{
			Success: false,
		}, status.Error(codes.Internal, err.Error())
	}

	return &desc.NeedOTPResponse{
		Success: true,
	}, nil
}
