// Package telemetry contains the control plane's bounded, typed and
// secret-safe observability primitives.  It deliberately has no exporter or
// transport dependency; callers decide how snapshots and events are exposed.
package telemetry

import (
	"errors"
	"fmt"
)

// ErrorCode is stable enough for callers and tests to branch on.  Error
// strings are intentionally generic and never include rejected values.
type ErrorCode string

const (
	ErrorInvalidDimension   ErrorCode = "invalid_dimension"
	ErrorInvalidStatus      ErrorCode = "invalid_status"
	ErrorInvalidCode        ErrorCode = "invalid_code"
	ErrorInvalidRetry       ErrorCode = "invalid_retry"
	ErrorInvalidTime        ErrorCode = "invalid_time"
	ErrorInvalidString      ErrorCode = "invalid_string"
	ErrorInvalidID          ErrorCode = "invalid_id"
	ErrorInvalidEvent       ErrorCode = "invalid_event"
	ErrorInvalidCapacity    ErrorCode = "invalid_capacity"
	ErrorUnknownMetric      ErrorCode = "unknown_metric"
	ErrorMetricKindMismatch ErrorCode = "metric_kind_mismatch"
	ErrorUnknownLabel       ErrorCode = "unknown_label"
	ErrorMissingLabel       ErrorCode = "missing_label"
	ErrorLabelValueRejected ErrorCode = "label_value_rejected"
	ErrorMetricOverflow     ErrorCode = "metric_overflow"
	ErrorMetricCardinality  ErrorCode = "metric_cardinality"
	ErrorInvalidObservation ErrorCode = "invalid_observation"
	ErrorClosed             ErrorCode = "closed"
	ErrorIdentityRequired   ErrorCode = "identity_required"
	ErrorIdentityMismatch   ErrorCode = "identity_mismatch"
	ErrorUnsafeField        ErrorCode = "unsafe_field"
	ErrorUnsupportedValue   ErrorCode = "unsupported_value"
)

// Error is a typed validation or bounded-resource error.
type Error struct {
	Code      ErrorCode
	Operation string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Operation == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Code)
}

func newError(code ErrorCode, operation string) error {
	return &Error{Code: code, Operation: operation}
}

func errorCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.Code
	}
	return ""
}

// ErrorCodeOf returns the stable branchable code carried by a telemetry
// validation or bounded-resource error. It returns an empty code for errors
// outside this package.
func ErrorCodeOf(err error) ErrorCode { return errorCode(err) }
