package auth

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestPurposeBoundReauthenticationProof(t *testing.T) {
	service := NewService(nil, nil, FakeWorkOSVerifier{}, []string{"0123456789abcdef0123456789abcdef"}, false)
	user := User{ID: "usr_test", WorkOSSubject: "workos_subject"}
	state, err := service.NewReauthState(user.ID, "config_recovery_export")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	service.SetOAuthStateCookie(recorder, state)
	request := httptest.NewRequest("POST", "/api/auth/workos/reauth/callback", nil)
	request.AddCookie(recorder.Result().Cookies()[0])
	proof, err := service.VerifyReauthentication(context.Background(), request, CallbackInput{Code: "workos_subject:user@example.test", State: state}, user, "config_recovery_export")
	if err != nil {
		t.Fatal(err)
	}
	proofRecorder := httptest.NewRecorder()
	service.SetReauthProofCookie(proofRecorder, proof)
	exportRequest := httptest.NewRequest("POST", "/api/config-sync/recovery-key/export", nil)
	exportRequest.AddCookie(proofRecorder.Result().Cookies()[0])
	if err := service.ValidateReauthProof(exportRequest, user.ID, "config_recovery_export"); err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateReauthProof(exportRequest, user.ID, "config_key_rotation"); err == nil {
		t.Fatal("proof was accepted for another purpose")
	}
}

func TestReauthenticationRejectsDifferentWorkOSSubject(t *testing.T) {
	service := NewService(nil, nil, FakeWorkOSVerifier{}, []string{"0123456789abcdef0123456789abcdef"}, false)
	user := User{ID: "usr_test", WorkOSSubject: "expected"}
	state, _ := service.NewReauthState(user.ID, "config_recovery_export")
	recorder := httptest.NewRecorder()
	service.SetOAuthStateCookie(recorder, state)
	request := httptest.NewRequest("POST", "/", nil)
	request.AddCookie(recorder.Result().Cookies()[0])
	if _, err := service.VerifyReauthentication(context.Background(), request, CallbackInput{Code: "other:user@example.test", State: state}, user, "config_recovery_export"); err == nil {
		t.Fatal("different WorkOS subject was accepted")
	}
}
