package favorites

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

const Max = 5

var ErrLimit = errors.New("favorite limit reached")
var ErrResourceNotFound = errors.New("favorite resource not found")

type Favorite struct {
	Kind       string    `json:"kind"`
	ResourceID string    `json:"resource_id"`
	CreatedAt  time.Time `json:"created_at"`
}

type Service struct{ store *db.DB }

func NewService(store *db.DB) *Service { return &Service{store: store} }

func (s *Service) List(ctx context.Context, userID string) ([]Favorite, error) {
	rows, err := s.store.Queries().ListUserFavorites(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list favorites: %w", err)
	}
	items := make([]Favorite, 0, len(rows))
	for _, row := range rows {
		items = append(items, Favorite{Kind: row.Kind, ResourceID: row.ResourceID, CreatedAt: row.CreatedAt})
	}
	return items, nil
}

func (s *Service) Set(ctx context.Context, userID, kind, resourceID string, favorite bool) error {
	kind, resourceID = strings.TrimSpace(kind), strings.TrimSpace(resourceID)
	if kind != "machine" && kind != "session" && kind != "preview" {
		return errors.New("unsupported favorite kind")
	}
	if resourceID == "" {
		return errors.New("favorite resource id is required")
	}
	return s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		deleteParams := dbsqlc.DeleteUserFavoriteParams{UserID: userID, Kind: kind, ResourceID: resourceID}
		if !favorite {
			_, err := tx.Queries().DeleteUserFavorite(ctx, deleteParams)
			return err
		}
		owned, err := tx.Queries().UserOwnsFavoriteResource(ctx, dbsqlc.UserOwnsFavoriteResourceParams{Kind: kind, OwnerUserID: userID, ResourceID: resourceID})
		if err != nil {
			return err
		}
		if !owned {
			return ErrResourceNotFound
		}
		if _, err := tx.Queries().LockUserForFavorites(ctx, userID); err != nil {
			return err
		}
		count, err := tx.Queries().CountUserFavorites(ctx, userID)
		if err != nil {
			return err
		}
		created, err := tx.Queries().CreateUserFavorite(ctx, dbsqlc.CreateUserFavoriteParams{UserID: userID, Kind: kind, ResourceID: resourceID})
		if err != nil {
			return err
		}
		if created == 0 {
			return nil
		}
		if count >= Max {
			return ErrLimit
		}
		return nil
	})
}
