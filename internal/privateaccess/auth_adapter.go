package privateaccess

import (
	"context"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type SQLMachineStateVerifier struct{ db *db.DB }

func NewSQLMachineStateVerifier(database *db.DB) (*SQLMachineStateVerifier, error) {
	if database == nil || database.Pool() == nil {
		return nil, fmt.Errorf("%w: machine state database is not open", ErrInvalid)
	}
	return &SQLMachineStateVerifier{db: database}, nil
}

func (v *SQLMachineStateVerifier) VerifyCurrentMachine(ctx context.Context, identity Identity, now time.Time) error {
	if v == nil || v.db == nil || ctx == nil || identity.InstallationGeneration == 0 {
		return ErrIdentityUnavailable
	}
	var ok bool
	err := v.db.Pool().QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM user_machines machines
		JOIN machine_control_sessions control ON control.machine_id = machines.id
		WHERE machines.id=$1 AND machines.user_id=$2 AND machines.installation_generation=$3
		  AND control.installation_generation=machines.installation_generation
		  AND control.credential_jti=$4 AND control.expires_at > $5
		  AND machines.state='online' AND machines.online
		  AND machines.deleted_at IS NULL AND machines.revoked_at IS NULL
	)`, identity.DeviceID, identity.AccountID, int64(identity.InstallationGeneration), identity.SessionID, now.UTC()).Scan(&ok)
	if err != nil {
		return ErrIdentityUnavailable
	}
	if !ok {
		return newDenied(ReasonDeviceRevoked)
	}
	return nil
}
