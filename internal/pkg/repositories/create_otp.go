package repositories

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

type CreateOTPRepository struct {
	db *redis.Client
}

func NewCreateOTPRepository(db *redis.Client) *CreateOTPRepository {
	return &CreateOTPRepository{db: db}
}

func (r *CreateOTPRepository) CreateOTP(ctx context.Context, userId, otp string) error {
	ttl := viper.GetDuration("otp.ttl_min")
	status := r.db.Set(ctx, userId, otp, time.Minute*ttl)
	if status.Err() != nil {
		slog.Error("Failed to set otp for user:", userId)
	}
	return status.Err()
}
