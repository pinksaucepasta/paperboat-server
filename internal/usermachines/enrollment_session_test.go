package usermachines

import "testing"

func TestShouldIssueCLIEnrollmentSession(t *testing.T) {
	if shouldIssueCLIEnrollmentSession("host") {
		t.Fatal("host enrollment must not issue an unused CLI session")
	}
	if !shouldIssueCLIEnrollmentSession("client") {
		t.Fatal("client enrollment must issue a CLI session")
	}
}
