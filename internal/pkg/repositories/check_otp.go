package repositories

import (
	"context"

	"github.com/redis/go-redis/v9"
)

type CheckOTPRepository struct {
	db *redis.Client
}

func NewCheckOTPRepository(db *redis.Client) *CheckOTPRepository {
	return &CheckOTPRepository{db: db}
}

func (r *CheckOTPRepository) GetOTP(ctx context.Context, userId string) string {
	otp := r.db.Get(ctx, userId)
	return otp.Val()
}
