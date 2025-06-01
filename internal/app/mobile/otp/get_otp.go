package otp

import (
	"context"
	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (i *Implementation) GetOTP(ctx context.Context, req *desc.GetOTPRequest) (*desc.GetOTPResponse, error) {
	if err := validateGetOTPRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return i.getOTP.GetOTP(ctx, req)
}

func validateGetOTPRequest(req *desc.GetOTPRequest) error {
	return validation.ValidateStruct(req,
		validation.Field(&req.PublicKey, validation.Required),
	)
}
