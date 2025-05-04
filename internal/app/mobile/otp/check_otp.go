package otp

import (
	"context"

	desc "github.com/PluT00/mobile-otp/internal/grpc/api/mobile-otp"
)

func (i *Implementation) CheckOTP(ctx context.Context, req *desc.CheckOTPRequest) (*desc.CheckOTPResponse, error) {
	return i.checkOTP.CheckOTP(ctx, req)
}
