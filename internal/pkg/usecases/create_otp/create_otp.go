package createotp

import (
	"context"
	"crypto/rand"

	"github.com/spf13/viper"

	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
)

type (
	CreateOTPRepository interface {
		CreateOTP(ctx context.Context, userId, otp string) error
	}

	UseCase struct {
		repository CreateOTPRepository
	}
)

func NewUseCase(repository CreateOTPRepository) *UseCase {
	return &UseCase{
		repository: repository,
	}
}

func (uc *UseCase) CreateOTP(ctx context.Context, req *desc.CreateOTPRequest) (*desc.CreateOTPResponse, error) {
	otp := genOTP()

	err := uc.repository.CreateOTP(ctx, req.GetId(), otp)
	if err != nil {
		return &desc.CreateOTPResponse{
			Success: false,
		}, err
	}

	return &desc.CreateOTPResponse{
		Success: true,
	}, nil
}

// genOTP - Генерация криптографически безопасного OTP длины установленной в конфиге
func genOTP() string {
	var dictionary string
	dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	var bytes = make([]byte, viper.GetInt("otp.len"))
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}
