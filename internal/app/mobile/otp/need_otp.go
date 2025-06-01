package otp

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"

	"github.com/go-ozzo/ozzo-validation/v4"
	"github.com/spf13/viper"

	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
)

func (i *Implementation) NeedOTP(ctx context.Context, req *desc.NeedOTPRequest) (*desc.NeedOTPResponse, error) {
	timeout := viper.GetDuration("grpc_listen.req_timeout_sec")
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Second*timeout)
	defer cancel()

	if err := validateNeedOTPRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return i.needOTP.NeedOTP(ctxTimeout, req)
}

func validateNeedOTPRequest(req *desc.NeedOTPRequest) error {
	return validation.ValidateStruct(req,
		validation.Field(&req.Id, validation.Required),
	)
}
