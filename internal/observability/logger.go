package observability

import (
	"context"
	"log/slog"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

func RequestID(ctx context.Context) string {
	if value, ok := ctx.Value(requestIDKey).(string); ok {
		return value
	}
	return ""
}

func LoggerWithRequest(ctx context.Context, logger *slog.Logger) *slog.Logger {
	if requestID := RequestID(ctx); requestID != "" {
		return logger.With("request_id", requestID)
	}
	return logger
}
