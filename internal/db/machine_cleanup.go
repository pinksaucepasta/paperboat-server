package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

// CleanupMachineDeviceTx fences device credentials and state in the owning
// deletion transaction. Personal and team lifecycle paths share this cleanup.
func CleanupMachineDeviceTx(ctx context.Context, tx *Tx, userID, userMachineID string, now time.Time) error {
	queries := tx.Queries()
	machineID := sql.NullString{String: userMachineID, Valid: true}
	revocationTime := sql.NullTime{Time: now, Valid: true}

	if _, err := queries.RevokeUserMachineE2EEKeys(ctx, dbsqlc.RevokeUserMachineE2EEKeysParams{
		RevocationTime: now, TargetUserID: userID, TargetMachineID: machineID,
	}); err != nil {
		return err
	}
	if _, err := queries.RevokeCLIClientSessionsForUserMachine(ctx, dbsqlc.RevokeCLIClientSessionsForUserMachineParams{
		RevocationTime: revocationTime, RevocationCause: sql.NullString{String: "device_removed", Valid: true}, TargetMachineID: machineID, TargetUserID: userID,
	}); err != nil {
		return err
	}
	if _, err := queries.RevokeCLIClientAccessTokensForUserMachine(ctx, dbsqlc.RevokeCLIClientAccessTokensForUserMachineParams{
		RevocationTime: revocationTime, TargetMachineID: machineID, TargetUserID: userID,
	}); err != nil {
		return err
	}
	if _, err := queries.RevokeCLIClientRefreshTokensForUserMachine(ctx, dbsqlc.RevokeCLIClientRefreshTokensForUserMachineParams{
		RevocationTime: revocationTime, TargetMachineID: machineID, TargetUserID: userID,
	}); err != nil {
		return err
	}
	if _, err := queries.RevokeUserMachinePeerAuthority(ctx, dbsqlc.RevokeUserMachinePeerAuthorityParams{
		TargetMachineID: userMachineID, TargetUserID: userID, RevocationTime: revocationTime,
	}); err != nil {
		return err
	}
	if _, err := queries.ExpireUserMachinePairings(ctx, dbsqlc.ExpireUserMachinePairingsParams{ExpiredAt: now, TargetMachineID: machineID}); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineEnrollments(ctx, dbsqlc.DeleteUserMachineEnrollmentsParams{ExpiredAt: now, TargetMachineID: machineID}); err != nil {
		return err
	}
	if _, err := queries.ExpireUserMachineDiagnosticUploadIntents(ctx, dbsqlc.ExpireUserMachineDiagnosticUploadIntentsParams{TargetMachineID: machineID, TargetUserID: userID}); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineControlSessions(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineControlRenewals(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineTransferDestinationDefault(ctx, dbsqlc.DeleteUserMachineTransferDestinationDefaultParams{TargetUserID: userID, TargetMachineID: userMachineID}); err != nil {
		return err
	}
	if _, err := queries.ClearProjectTerminalTransferDestinationsForMachine(ctx, dbsqlc.ClearProjectTerminalTransferDestinationsForMachineParams{ExpiredAt: now, TargetMachineID: machineID}); err != nil {
		return err
	}
	if _, err := queries.ClearUserMachineTerminalTransferDestinationsForMachine(ctx, dbsqlc.ClearUserMachineTerminalTransferDestinationsForMachineParams{ExpiredAt: now, TargetMachineID: machineID}); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineTerminalSessionOperations(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineTerminalSessions(ctx, dbsqlc.DeleteUserMachineTerminalSessionsParams{ExpiredAt: now, TargetMachineID: userMachineID}); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineAvailabilityOperations(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineUpdateObservation(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.ExpireUserMachineMaintenanceApprovals(ctx, dbsqlc.ExpireUserMachineMaintenanceApprovalsParams{ExpiredAt: now, TargetMachineID: userMachineID}); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineRelaySelectionStates(ctx, dbsqlc.DeleteUserMachineRelaySelectionStatesParams{TargetUserID: userID, TargetMachineID: userMachineID}); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineSSHHostKeys(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineSSHHostKeySets(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineSSHHostKeyOwners(ctx, userMachineID); err != nil {
		return err
	}
	if _, err := queries.DeleteUserMachineSSHTarget(ctx, userMachineID); err != nil {
		return err
	}
	return nil
}

func RevokeMachineEnvironmentTx(ctx context.Context, tx *Tx, environmentID string, now time.Time) error {
	environment, err := tx.Queries().GetControlEnvironment(ctx, environmentID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && environment.DesiredState != "revoked" {
		if _, err := tx.Queries().UpdateControlEnvironmentDesiredState(ctx, dbsqlc.UpdateControlEnvironmentDesiredStateParams{DesiredState: "revoked", Now: now, ID: environmentID, ExpectedVersion: environment.DesiredVersion}); err != nil {
			return err
		}
	}
	if _, err := tx.Queries().RevokeControlHelpersForEnvironment(ctx, dbsqlc.RevokeControlHelpersForEnvironmentParams{RevokedAt: now, EnvironmentID: environmentID}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlHelperEnrollmentsForEnvironment(ctx, dbsqlc.RevokeControlHelperEnrollmentsForEnvironmentParams{RevokedAt: sql.NullTime{Time: now, Valid: true}, EnvironmentID: environmentID}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlConnectorForEnvironment(ctx, dbsqlc.RevokeControlConnectorForEnvironmentParams{RevokedAt: now, EnvironmentID: environmentID}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlRoutesForEnvironment(ctx, dbsqlc.RevokeControlRoutesForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
		return err
	}
	if _, err = tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
		return err
	}
	if _, err = tx.Queries().RevokeControlConfigRepositoryAccessForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
		return err
	}
	if _, err = tx.Queries().RevokeControlConfigRepositoryLeasesForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryLeasesForEnvironmentParams{EnvironmentID: sql.NullString{String: environmentID, Valid: true}, Now: sql.NullTime{Time: now, Valid: true}}); err != nil {
		return err
	}
	return nil
}

// RequireVaultRotationTx preserves the existing device-removal key fences.
func RequireVaultRotationTx(ctx context.Context, tx *Tx, account string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(160235)`); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `INSERT INTO environment_vault_personal_epochs(account_id,key_epoch,rotation_required) SELECT $1,1,true WHERE EXISTS(SELECT 1 FROM environment_password_vaults WHERE account_id=$1) ON CONFLICT(account_id) DO UPDATE SET rotation_required=true WHERE NOT environment_vault_personal_epochs.rotation_required`, account)
	if err != nil {
		return err
	}
	if command.RowsAffected() > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO environment_vault_projection_fences(machine_id,generation) SELECT id,1 FROM user_machines WHERE user_id=$1 ON CONFLICT(machine_id) DO UPDATE SET generation=environment_vault_projection_fences.generation+1`, account); err != nil {
			return err
		}
	}
	// A revoked device could have held every currently granted team key in its vault.
	// Fence each affected team, including projections owned by other team members.
	_, err = tx.Exec(ctx, `WITH affected AS (UPDATE environment_vault_teams t SET rotation_required=true WHERE NOT rotation_required AND EXISTS(SELECT 1 FROM team_members m JOIN environment_vault_team_members e USING(team_id,account_id) WHERE m.team_id=t.team_id AND m.account_id=$1 AND m.active AND e.grant_epoch=t.key_epoch) RETURNING team_id), advanced AS (UPDATE teams SET generation=generation+1 WHERE team_id IN(SELECT team_id FROM affected)) INSERT INTO environment_vault_projection_fences(machine_id,generation) SELECT DISTINCT p.machine_id,1 FROM environment_vault_projection_sources p JOIN affected a ON p.owner_kind='team' AND p.owner_id=a.team_id ON CONFLICT(machine_id) DO UPDATE SET generation=environment_vault_projection_fences.generation+1`, account)
	return err
}
