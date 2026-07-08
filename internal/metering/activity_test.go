package metering

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRecordActivityRejectsUnapprovedSource(t *testing.T) {
	repo := &RuntimeRepository{}
	err := repo.RecordActivity(context.Background(), "prj_activity", time.Now(), "browser_ping", nil)
	if err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("RecordActivity error = %v, want source rejection", err)
	}
}
