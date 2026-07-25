package httpapi

import "testing"

func TestSafeLogPathRedactsDeviceUserCodes(t *testing.T) {
	for input, want := range map[string]string{
		"/v1/auth/device/requests/ABCD-EFGH":         "/v1/auth/device/requests/{user_code}",
		"/v1/auth/device/requests/ABCD-EFGH/approve": "/v1/auth/device/requests/{user_code}/approve",
		"/v1/auth/device/requests/ABCD-EFGH/deny":    "/v1/auth/device/requests/{user_code}/deny",
		"/v1/projects/prj_1":                         "/v1/projects/prj_1",
	} {
		if got := safeLogPath(input); got != want {
			t.Errorf("safeLogPath(%q)=%q want=%q", input, got, want)
		}
	}
}
