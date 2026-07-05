package testutil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type Clock struct {
	now int64
}

func NewTestServer(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

type FakeReadiness struct {
	Err error
}

func (f FakeReadiness) Ready(context.Context) error {
	return f.Err
}
