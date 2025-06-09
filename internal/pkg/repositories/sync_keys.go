package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PluT00/mobile-otp/internal/pkg/models"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"time"
)

type SyncKeysRepository struct {
	db *redis.Client
}

func NewSyncKeysRepository(client *redis.Client) *SyncKeysRepository {
	return &SyncKeysRepository{
		db: client,
	}
}

func (r *SyncKeysRepository) SetKeys(ctx context.Context, nonce int32, keys models.Keys) error {
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		slog.Error("Failed to marshal keys: ", err)
		return errors.New("failed to marshal keys")
	}

	redisKey := fmt.Sprintf("keys:%d", nonce)
	if err := r.db.Set(ctx, redisKey, keysJSON, 30*time.Second).Err(); err != nil {
		slog.Error("Failed to store keys in Redis: ", err)
		return errors.New("failed to store keys in Redis")
	}

	return nil
}
