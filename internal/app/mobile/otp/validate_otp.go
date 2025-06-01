package otp

import (
	"context"
	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (i *Implementation) ValidateOTP(ctx context.Context, req *desc.ValidateOTPRequest) (*desc.ValidateOTPResponse, error) {
	if err := validateValidateOTPRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return i.validateOTP.ValidateOTP(ctx, req)
}

func validateValidateOTPRequest(req *desc.ValidateOTPRequest) error {
	return validation.ValidateStruct(req,
		validation.Field(&req.Id, validation.Required),
		validation.Field(&req.Otp, validation.Required),
	)
}
