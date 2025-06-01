package repositories

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type ValidateOTPRepository struct {
	db *redis.Client
}

func NewValidateOTPRepository(db *redis.Client) *ValidateOTPRepository {
	return &ValidateOTPRepository{db: db}
}

func (r *ValidateOTPRepository) GetOTP(ctx context.Context, userId string) string {
	path := fmt.Sprintf("otp:%s", userId)
	otp := r.db.Get(ctx, path)
	return otp.Val()
}

func (r *ValidateOTPRepository) IncrRetryOTP(ctx context.Context, userId string) (int, error) {
	path := fmt.Sprintf("otp_retry:%s", userId)
	retry, err := r.db.Incr(ctx, path).Result()
	if err != nil {
		return 0, err
	}
	return int(retry), nil
}

func (r *ValidateOTPRepository) DeleteOTP(ctx context.Context, userId string) {
	path := fmt.Sprintf("otp:%s", userId)
	retryPath := fmt.Sprintf("otp_retry:%s", userId)
	r.db.Del(ctx, path)
	r.db.Del(ctx, retryPath)
}
