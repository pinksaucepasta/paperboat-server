package previewdomain

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
)

// PreviewCarrierAliasProjector publishes only aliases that are backed by the
// current active preview lease, verified DNS ownership, and an active
// certificate distribution record. The edge node and process epoch are
// supplied by the authenticated edge request and are checked against the
// exact durable certificate distribution tuple before any projection is
// returned. RouteID and PreviewGeneration remain bound by the map key, so a
// domain can never be attached to a different route admission.
type PreviewCarrierAliasProjector struct {
	repository PreviewDomainRepository
	readiness  PreviewCertificateReadiness
	now        func() time.Time
}

// PreviewCertificateReadiness is the narrow durable fence required before a
// preview alias can be published to an edge admission. Implementations must
// compare every supplied identity and generation, including the authenticated
// edge process and current attachment generation.
type PreviewCertificateReadiness interface {
	PreviewCertificateReady(context.Context, string, string, string, string, uint64, uint64, uint64, tunnelcert.DistributionTarget, time.Time) (bool, error)
}

func NewPreviewCarrierAliasProjector(repository PreviewDomainRepository, readiness PreviewCertificateReadiness, now func() time.Time) (*PreviewCarrierAliasProjector, error) {
	if repository == nil {
		return nil, fmt.Errorf("%w: alias repository is required", ErrInvalidInput)
	}
	if readiness == nil {
		return nil, fmt.Errorf("%w: certificate readiness is required", ErrInvalidInput)
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &PreviewCarrierAliasProjector{repository: repository, readiness: readiness, now: now}, nil
}

var _ previewattachment.PreviewCarrierAliasProjector = (*PreviewCarrierAliasProjector)(nil)

func (p *PreviewCarrierAliasProjector) ProjectPreviewCarrierAliases(ctx context.Context, edgeNodeID, edgeProcessEpoch string, bindings []previewattachment.PreviewCarrierAliasBinding, at time.Time) (map[previewattachment.PreviewCarrierAliasBinding][]previewattachment.CarrierAlias, error) {
	if p == nil || p.repository == nil || p.readiness == nil || !validProjectionID(edgeNodeID) || !validProjectionID(edgeProcessEpoch) {
		return nil, ErrInvalidInput
	}
	if err := (tunnelcert.DistributionTarget{NodeID: edgeNodeID, ProcessEpoch: edgeProcessEpoch, Generation: 1}).Validate(); err != nil {
		return nil, fmt.Errorf("%w: edge target is invalid", ErrInvalidInput)
	}
	if len(bindings) > previewattachment.EdgeAdmissionMaxItems {
		return nil, ErrInvalidInput
	}
	if at.IsZero() {
		at = p.now().UTC()
	}
	result := make(map[previewattachment.PreviewCarrierAliasBinding][]previewattachment.CarrierAlias, len(bindings))
	seen := make(map[previewattachment.PreviewCarrierAliasBinding]struct{}, len(bindings))
	for _, binding := range bindings {
		if !validProjectionID(binding.AccountID) || !validProjectionID(binding.PreviewID) || !validProjectionID(binding.RouteID) || binding.PreviewGeneration == 0 || binding.AttachmentGeneration == 0 {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[binding]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[binding] = struct{}{}
		edgeTarget := tunnelcert.DistributionTarget{NodeID: edgeNodeID, ProcessEpoch: edgeProcessEpoch, Generation: binding.AttachmentGeneration}
		if err := edgeTarget.Validate(); err != nil {
			return nil, fmt.Errorf("%w: edge target is invalid", ErrInvalidInput)
		}
		records, err := p.repository.ReadyAliases(ctx, binding.AccountID, binding.PreviewID, at.UTC())
		if err != nil {
			return nil, err
		}
		aliases := make([]previewattachment.CarrierAlias, 0, len(records))
		for _, record := range records {
			row := record.Domain
			if row.AccountID != binding.AccountID || row.PreviewID != binding.PreviewID || row.PreviewGeneration != int64(binding.PreviewGeneration) || row.DeletedAt.Valid || row.OwnershipState != "verified" || row.ConflictState != "clear" || row.CertificateState != "ready" || row.Generation < 1 || record.CertificateGeneration < 1 || record.CertificateReference == "" {
				continue
			}
			ready, readinessErr := p.readiness.PreviewCertificateReady(ctx, binding.AccountID, row.ID, binding.PreviewID, row.Hostname, uint64(row.PreviewGeneration), uint64(row.Generation), uint64(record.CertificateGeneration), edgeTarget, at.UTC())
			if readinessErr != nil {
				return nil, readinessErr
			}
			if !ready {
				continue
			}
			alias := previewattachment.CarrierAlias{
				DomainID:              row.ID,
				Hostname:              row.Hostname,
				MatchType:             row.MatchType,
				PreviewGeneration:     uint64(row.PreviewGeneration),
				DomainGeneration:      uint64(row.Generation),
				CertificateGeneration: uint64(record.CertificateGeneration),
			}
			if row.MatchType == "one_label_wildcard" {
				labels := 1
				alias.WildcardLabels = &labels
			} else if row.MatchType != "exact" {
				return nil, ErrInvalidInput
			}
			if err := alias.Validate(binding.PreviewGeneration); err != nil {
				return nil, err
			}
			aliases = append(aliases, alias)
		}
		sort.Slice(aliases, func(i, j int) bool {
			if aliases[i].Hostname != aliases[j].Hostname {
				return aliases[i].Hostname < aliases[j].Hostname
			}
			return aliases[i].DomainID < aliases[j].DomainID
		})
		result[binding] = aliases
	}
	return result, nil
}

func validProjectionID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
