package repositories

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"log/slog"
	"time"
)

type GetOTPRepository struct {
	db *redis.Client
}

func NewGetOTPRepository(db *redis.Client) *GetOTPRepository {
	return &GetOTPRepository{
		db: db,
	}
}

func (r *GetOTPRepository) GetNeedOTP(ctx context.Context, userId string) (bool, error) {
	path := fmt.Sprintf("need_otp:%s", userId)
	needOTP := r.db.Get(ctx, path)
	need, err := needOTP.Bool()
	if err != nil {
		return false, err
	}
	if !need {
		return false, nil
	}
	return true, nil
}

func (r *GetOTPRepository) SetOTP(ctx context.Context, userId, otp string) error {
	ttl := viper.GetDuration("otp.ttl_min")
	path := fmt.Sprintf("otp:%s", userId)

	status := r.db.Set(ctx, path, otp, time.Minute*ttl)
	if status.Err() != nil {
		slog.Error("Failed to set otp for user: " + userId)
		return status.Err()
	}

	return nil
}

func (r *GetOTPRepository) DeleteNeedOTP(ctx context.Context, userId string) {
	path := fmt.Sprintf("need_otp:%s", userId)
	r.db.Del(ctx, path)
}
