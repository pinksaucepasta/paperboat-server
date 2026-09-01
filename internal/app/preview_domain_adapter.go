package app

import (
	"context"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

type previewDomainBatchCreatorAdapter struct {
	repository *previewdomain.SQLRepository
}

func (a previewDomainBatchCreatorAdapter) CreateForPreviewTx(ctx context.Context, tx *db.Tx, input previewtunnelstore.PreviewDomainBatchInput) error {
	if a.repository == nil {
		return previewdomain.ErrInvalidInput
	}
	domains := make([]previewdomain.Request, len(input.Domains))
	for index, domain := range input.Domains {
		domains[index] = previewdomain.Request{
			Hostname: domain.Hostname, Provider: domain.Provider, CertificateStrategy: domain.CertificateStrategy,
		}
	}
	_, err := a.repository.CreateForPreviewTx(ctx, tx, previewdomain.BatchCreateRequest{
		AccountID: input.AccountID, PreviewID: input.PreviewID, PreviewGeneration: input.PreviewGeneration,
		StableEndpoint: input.StableEndpoint, Domains: domains, ActorID: input.ActorID, ActorType: input.ActorType,
		RequestID: input.RequestID, CorrelationID: input.CorrelationID, Now: input.Now,
	})
	return err
}

var _ previewtunnelstore.PreviewDomainBatchCreator = previewDomainBatchCreatorAdapter{}
