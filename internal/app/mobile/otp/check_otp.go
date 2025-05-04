package otp

import (
	"context"
	"errors"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
)

func (i *Implementation) CheckOTP(ctx context.Context, req *desc.CheckOTPRequest) (*desc.CheckOTPResponse, error) {
	if err := validateCheckOTP(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return i.checkOTP.CheckOTP(ctx, req)
}

func validateCheckOTP(req *desc.CheckOTPRequest) error {
	if req == nil {
		return errors.New("empty request")
	}

	if err := validation.ValidateStruct(req,
		validation.Field(&req.Id, validation.Required),
		validation.Field(&req.Otp, validation.Required),
		validation.Field(&req.Otp.Code, validation.Required),
	); err != nil {
		return err
	}
	return nil
}
