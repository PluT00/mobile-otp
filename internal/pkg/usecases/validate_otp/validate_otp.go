package validate_otp

import (
	"context"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
)

type (
	ValidateOTPRepository interface {
		GetOTP(ctx context.Context, userId string) string
		DeleteOTP(ctx context.Context, userId string)
		IncrRetryOTP(ctx context.Context, userId string) (int, error)
	}

	UseCase struct {
		repository ValidateOTPRepository
	}
)

func NewUseCase(repository ValidateOTPRepository) *UseCase {
	return &UseCase{
		repository: repository,
	}
}

func (uc *UseCase) ValidateOTP(ctx context.Context, req *desc.ValidateOTPRequest) (*desc.ValidateOTPResponse, error) {
	otp := uc.repository.GetOTP(ctx, req.GetId())
	if otp == "" {
		return &desc.ValidateOTPResponse{Ok: false}, status.Error(codes.NotFound, "uc.repository.GetOTP: OTP not found; you must request otp generation first")
	}

	err := bcrypt.CompareHashAndPassword([]byte(otp), []byte(req.GetOtp().GetCode()))
	if err != nil {
		retry, err := uc.repository.IncrRetryOTP(ctx, req.GetId())
		if err != nil {
			return &desc.ValidateOTPResponse{Ok: false}, status.Errorf(codes.Internal, "uc.repository.IncrRetryOTP: %v", err)
		}
		if retry >= viper.GetInt("otp.max_retry") {
			uc.repository.DeleteOTP(ctx, req.GetId())
			return &desc.ValidateOTPResponse{Ok: false}, status.Error(codes.ResourceExhausted, "OTP retries limit reached")
		}
		return &desc.ValidateOTPResponse{
			Ok: false,
		}, nil
	}

	uc.repository.DeleteOTP(ctx, req.GetId())
	return &desc.ValidateOTPResponse{
		Ok: true,
	}, nil
}
