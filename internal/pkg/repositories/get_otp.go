package repositories

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
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

	hash, err := bcrypt.GenerateFromPassword([]byte(otp), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt.GenerateFromPassword: %w", err)
	}

	status := r.db.Set(ctx, path, hash, time.Minute*ttl)
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
