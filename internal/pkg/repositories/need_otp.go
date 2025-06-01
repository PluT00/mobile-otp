package repositories

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

type NeedOTPRepository struct {
	db *redis.Client
}

func NewNeedOTPRepository(db *redis.Client) *NeedOTPRepository {
	return &NeedOTPRepository{db: db}
}

func (r *NeedOTPRepository) NeedOTP(ctx context.Context, userId string) error {
	ttl := viper.GetDuration("otp.ttl_min")
	path := fmt.Sprintf("need_otp:%s", userId)

	status := r.db.Set(ctx, path, true, time.Minute*ttl)
	if status.Err() != nil {
		slog.Error("Failed to set need_otp for user: " + userId)
	}

	return status.Err()
}
