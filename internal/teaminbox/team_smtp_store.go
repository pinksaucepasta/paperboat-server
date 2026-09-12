package teaminbox

import (
	"context"
	"net"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

func authorizeSMTPAdmin(ctx context.Context, tx *db.Tx, account, team string) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM teams t JOIN team_members m USING(team_id) WHERE t.team_id=$2 AND t.deleted_at IS NULL AND m.account_id=$1 AND m.active AND (t.owner_account=$1 OR m.role='admin'))`, account, team).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}

func (s *Service) TeamSMTP(ctx context.Context, account, team string) (SMTPConfig, error) {
	if !safeID.MatchString(account) || !safeID.MatchString(team) {
		return SMTPConfig{}, ErrInvalid
	}
	var out SMTPConfig
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeSMTPAdmin(ctx, tx, account, team); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT host,port,username,from_address,tls_mode,generation,password_ciphertext IS NOT NULL FROM team_receipt_smtp WHERE team_id=$1`, team).Scan(&out.Host, &out.Port, &out.Username, &out.FromAddress, &out.TLSMode, &out.Generation, &out.PasswordStored)
		if noRows(err) {
			out = SMTPConfig{Port: 587, TLSMode: "starttls", Generation: 1}
			return nil
		}
		return err
	})
	return out, err
}

func (s *Service) SetTeamSMTP(ctx context.Context, account, team string, config SMTPConfig, expected uint64) (SMTPConfig, error) {
	if !safeID.MatchString(account) || !safeID.MatchString(team) || strings.TrimSpace(s.encryptionKey) == "" {
		return SMTPConfig{}, ErrInvalid
	}
	config.Host = strings.ToLower(strings.TrimSpace(config.Host))
	config.Username = strings.TrimSpace(config.Username)
	config.FromAddress = strings.TrimSpace(config.FromAddress)
	if config.Password != "" {
		if _, err := NewSMTPReceiptSender(config); err != nil {
			return SMTPConfig{}, err
		}
	} else if !smtpHostname.MatchString(config.Host) || net.ParseIP(config.Host) != nil || config.Port != 465 && config.Port != 587 || config.TLSMode != "implicit" && config.TLSMode != "starttls" || config.Username == "" || len(config.Username) > 320 || strings.ContainsAny(config.Username, "\r\n\x00") || !validMailbox(config.FromAddress) {
		return SMTPConfig{}, ErrInvalid
	}
	if expected == 0 {
		expected = 1
	}
	var out SMTPConfig
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeSMTPAdmin(ctx, tx, account, team); err != nil {
			return err
		}
		var encrypted []byte
		if config.Password != "" {
			var err error
			encrypted, err = secrets.Encrypt(s.encryptionKey, config.Password)
			if err != nil {
				return err
			}
		}
		err := tx.QueryRow(ctx, `INSERT INTO team_receipt_smtp(team_id,host,port,username,password_ciphertext,from_address,tls_mode,generation,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,1,now())
			ON CONFLICT(team_id) DO UPDATE SET host=EXCLUDED.host,port=EXCLUDED.port,username=EXCLUDED.username,password_ciphertext=coalesce(EXCLUDED.password_ciphertext,team_receipt_smtp.password_ciphertext),from_address=EXCLUDED.from_address,tls_mode=EXCLUDED.tls_mode,generation=team_receipt_smtp.generation+1,updated_at=now()
			WHERE team_receipt_smtp.generation=$8 AND (EXCLUDED.password_ciphertext IS NOT NULL OR team_receipt_smtp.password_ciphertext IS NOT NULL)
			RETURNING host,port,username,from_address,tls_mode,generation,password_ciphertext IS NOT NULL`, team, config.Host, config.Port, config.Username, encrypted, config.FromAddress, config.TLSMode, expected).Scan(&out.Host, &out.Port, &out.Username, &out.FromAddress, &out.TLSMode, &out.Generation, &out.PasswordStored)
		if noRows(err) {
			return ErrConflict
		}
		return err
	})
	return out, err
}

func (s *Service) DeleteTeamSMTP(ctx context.Context, account, team string, expected uint64) error {
	if !safeID.MatchString(account) || !safeID.MatchString(team) || expected == 0 {
		return ErrInvalid
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeSMTPAdmin(ctx, tx, account, team); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `DELETE FROM team_receipt_smtp WHERE team_id=$1 AND generation=$2`, team, expected)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	})
}

func (s *Service) teamSMTPSender(ctx context.Context, team string) (ReceiptSender, error) {
	if s.encryptionKey == "" {
		return nil, nil
	}
	var config SMTPConfig
	var encrypted []byte
	err := s.db.SQL().QueryRowContext(ctx, `SELECT host,port,username,password_ciphertext,from_address,tls_mode FROM paperboat.team_receipt_smtp WHERE team_id=$1`, team).Scan(&config.Host, &config.Port, &config.Username, &encrypted, &config.FromAddress, &config.TLSMode)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	config.Password, err = secrets.Decrypt(s.encryptionKey, encrypted)
	if err != nil {
		return nil, err
	}
	return s.smtpFactory(config)
}
