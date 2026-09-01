package db

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ValidateIsolatedTestDSN checks the safety contract shared by every
// PostgreSQL integration test. An explicitly enabled test must name a
// PostgreSQL URI whose database ends in _test, and it must not point at the
// configured application database. Keeping this check in one place prevents
// individual acceptance suites from drifting into unsafe destructive setup.
//
// The test database name is the repository's explicit isolation marker. The
// host and port comparison also catches a test URI that uses a different user
// or TLS query parameters while still targeting the same database server.
func ValidateIsolatedTestDSN(raw, production string) error {
	testURI, err := parseTestDSN(raw, "PAPERBOAT_TEST_DATABASE_DSN")
	if err != nil {
		return err
	}
	if strings.TrimSpace(production) == "" {
		return nil
	}
	productionURI, err := parseTestDSNAllowNonTest(production, "PAPERBOAT_DATABASE_DSN")
	if err != nil {
		return err
	}
	if sameDatabaseTarget(testURI, productionURI) {
		return errors.New("refusing to run integration tests against PAPERBOAT_DATABASE_DSN")
	}
	return nil
}

func parseTestDSN(raw, variable string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s is required when the integration test is enabled", variable)
	}
	u, err := parsePostgresURI(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be a valid PostgreSQL URI: %w", variable, err)
	}
	databaseName := strings.Trim(u.Path, "/")
	if databaseName == "" || !strings.HasSuffix(strings.ToLower(databaseName), "_test") {
		return nil, fmt.Errorf("%s must name an isolated *_test database", variable)
	}
	return u, nil
}

func parseTestDSNAllowNonTest(raw, variable string) (*url.URL, error) {
	u, err := parsePostgresURI(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s must be a valid PostgreSQL URI: %w", variable, err)
	}
	return u, nil
}

func parsePostgresURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || u.Hostname() == "" || strings.Trim(u.Path, "/") == "" {
		if err == nil {
			err = errors.New("scheme, host, and database name are required")
		}
		return nil, err
	}
	if u.User != nil {
		if _, err := url.QueryUnescape(u.User.Username()); err != nil {
			return nil, errors.New("invalid username encoding")
		}
		if password, set := u.User.Password(); set {
			if _, err := url.QueryUnescape(password); err != nil {
				return nil, errors.New("invalid password encoding")
			}
		}
	}
	return u, nil
}

func sameDatabaseTarget(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b) && strings.EqualFold(strings.Trim(a.Path, "/"), strings.Trim(b.Path, "/"))
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	return "5432"
}
