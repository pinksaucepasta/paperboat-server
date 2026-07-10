package httpapi

import "testing"

func TestSafeLogPathRedactsDeviceUserCodes(t *testing.T) {
	for input, want := range map[string]string{
		"/api/auth/device/requests/ABCD-EFGH":         "/api/auth/device/requests/{user_code}",
		"/api/auth/device/requests/ABCD-EFGH/approve": "/api/auth/device/requests/{user_code}/approve",
		"/api/auth/device/requests/ABCD-EFGH/deny":    "/api/auth/device/requests/{user_code}/deny",
		"/api/projects/prj_1":                         "/api/projects/prj_1",
	} {
		if got := safeLogPath(input); got != want {
			t.Errorf("safeLogPath(%q)=%q want=%q", input, got, want)
		}
	}
}
