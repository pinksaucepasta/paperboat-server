package teaminbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type ReceiptMessage struct {
	IdempotencyKey string
	To             string
	Subject        string
	Text           string
}

type ReceiptSender interface {
	SendReceipt(context.Context, ReceiptMessage) (providerMessageID string, err error)
}

type ReceiptWorker struct {
	service  *Service
	sender   ReceiptSender
	interval time.Duration
}

func NewReceiptWorker(service *Service, sender ReceiptSender, interval time.Duration) (*ReceiptWorker, error) {
	if service == nil {
		return nil, ErrInvalid
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &ReceiptWorker{service: service, sender: sender, interval: interval}, nil
}

func (w *ReceiptWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if err := w.DeliverOne(ctx); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *ReceiptWorker) DeliverOne(ctx context.Context) error {
	now := w.service.now().UTC()
	var requestID, recipient, team, email string
	var fileCount, attempts int
	err := w.service.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, `WITH candidate AS (SELECT o.request_id FROM team_inbox_receipt_outbox o WHERE o.attempts<5 AND o.next_attempt_at<=$1 AND (o.status IN ('pending','failed') OR o.status='delivering' AND o.updated_at<$1-interval '5 minutes') ORDER BY o.next_attempt_at,o.request_id FOR UPDATE SKIP LOCKED LIMIT 1), claimed AS (UPDATE team_inbox_receipt_outbox o SET status='delivering',attempts=attempts+1,updated_at=$1 FROM candidate WHERE o.request_id=candidate.request_id RETURNING o.request_id,o.recipient_account,o.attempts) SELECT claimed.request_id,claimed.recipient_account,r.team_id,claimed.attempts,u.primary_email,jsonb_array_length(r.manifest) FROM claimed JOIN users u ON u.id=claimed.recipient_account JOIN team_inbox_requests r ON r.request_id=claimed.request_id`, now).Scan(&requestID, &recipient, &team, &attempts, &email, &fileCount)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	_ = recipient
	message := ReceiptMessage{IdempotencyKey: requestID, To: email, Subject: "Files received in your Paperboat Inbox", Text: fmt.Sprintf("Paperboat received %d file(s) from an authorized teammate. Open your Paperboat Inbox to view them.", fileCount)}
	sender, sendErr := w.service.teamSMTPSender(ctx, team)
	if sendErr == nil && sender == nil {
		sender = w.sender
	}
	var providerID string
	if sendErr == nil && sender == nil {
		sendErr = errors.New("receipt email delivery is not configured")
	}
	if sendErr == nil {
		providerID, sendErr = sender.SendReceipt(ctx, message)
	}
	if sendErr == nil && providerID == "" {
		sendErr = errors.New("email provider returned no message ID")
	}
	if sendErr == nil {
		_, err = w.service.db.SQL().ExecContext(ctx, `UPDATE paperboat.team_inbox_receipt_outbox SET status='delivered',provider_message_id=$2,last_error_code=NULL,updated_at=$3 WHERE request_id=$1 AND status='delivering'`, requestID, providerID, w.service.now().UTC())
		return err
	}
	status := "failed"
	next := now.Add(time.Duration(1<<min(attempts, 5)) * time.Second)
	if attempts >= 5 {
		next = now.Add(100 * 365 * 24 * time.Hour)
	}
	_, err = w.service.db.SQL().ExecContext(ctx, `UPDATE paperboat.team_inbox_receipt_outbox SET status=$2,last_error_code='delivery_failed',next_attempt_at=$3,updated_at=$4 WHERE request_id=$1 AND status='delivering'`, requestID, status, next, w.service.now().UTC())
	return err
}
