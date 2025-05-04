package otp

import (
	"context"
	"errors"
	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (i *Implementation) CreateOTP(ctx context.Context, req *desc.CreateOTPRequest) (*desc.CreateOTPResponse, error) {
	if err := validateCreateOTP(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return i.createOTP.CreateOTP(ctx, req)
}

func validateCreateOTP(req *desc.CreateOTPRequest) error {
	if req == nil {
		return errors.New("empty request")
	}

	if err := validation.ValidateStruct(req,
		validation.Field(&req.Id, validation.Required),
	); err != nil {
		return err
	}
	return nil
}
