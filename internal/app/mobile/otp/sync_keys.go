package otp

import (
	"context"
	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (i *Implementation) SyncKeys(ctx context.Context, req *desc.SyncKeysRequest) (*desc.SyncKeysResponse, error) {
	if err := validateSyncKeysRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return i.syncKeys.SyncKeys(ctx, req)
}

func validateSyncKeysRequest(req *desc.SyncKeysRequest) error {
	return validation.ValidateStruct(req,
		validation.Field(&req.PublicKey, validation.Required),
		validation.Field(&req.Nonce, validation.Required),
	)
}
