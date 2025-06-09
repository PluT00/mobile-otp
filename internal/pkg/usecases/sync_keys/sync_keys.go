package sync_keys

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	desc "github.com/PluT00/mobile-otp/internal/grpc/github.com/PluT00/mobile-otp/api/mobile-otp"
	"github.com/PluT00/mobile-otp/internal/pkg/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
)

type (
	SyncKeysRepository interface {
		SetKeys(ctx context.Context, nonce int32, keys models.Keys) error
	}

	UseCase struct {
		repository SyncKeysRepository
	}
)

func NewUseCase(repository SyncKeysRepository) *UseCase {
	return &UseCase{
		repository: repository,
	}
}

func (uc *UseCase) SyncKeys(ctx context.Context, req *desc.SyncKeysRequest) (*desc.SyncKeysResponse, error) {
	// Decode client public key
	clientPubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(clientPubKeyBytes) != 65 || clientPubKeyBytes[0] != 0x04 {
		return nil, status.Error(codes.InvalidArgument, "invalid client public key")
	}

	// Generate server ECDH key pair (P-256)
	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("Failed to generate server key: ", err)
		return nil, status.Error(codes.Internal, "failed to generate server key")
	}
	serverPubKey := privKey.PublicKey()

	serverPubKeyBytes := serverPubKey.Bytes()
	serverPubKeyBase64 := base64.StdEncoding.EncodeToString(serverPubKeyBytes)

	keys := models.Keys{
		ClientPubKey:  req.PublicKey,
		ServerPrivKey: base64.StdEncoding.EncodeToString(privKey.Bytes()),
		ServerPubKey:  serverPubKeyBase64,
	}

	err = uc.repository.SetKeys(ctx, req.Nonce, keys)
	if err != nil {
		slog.Error("Failed to set server keys: ", err)
	}

	return &desc.SyncKeysResponse{
		PublicKey: serverPubKeyBase64,
	}, nil
}
