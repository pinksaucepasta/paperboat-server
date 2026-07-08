package httpapi

import (
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

func dashboardUsageSummary(billingService *billing.Service, projectService *projects.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		usage, err := billingService.Usage(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		items, err := projectService.List(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		states := map[string]int{}
		running := 0
		restartRequired := 0
		for _, project := range items {
			states[project.State]++
			if project.State == "running" || project.State == "starting" || project.State == "restarting" {
				running++
			}
			if project.RestartRequired {
				restartRequired++
			}
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
			"credits": map[string]any{
				"balance": usage.CreditsBalance,
			},
			"storage": map[string]any{
				"included_gb":  usage.IncludedStorageGB,
				"purchased_gb": usage.PurchasedStorageGB,
				"allocated_gb": usage.AllocatedStorageGB,
				"available_gb": usage.AvailableStorageGB,
			},
			"projects": map[string]any{
				"total":             len(items),
				"running":           running,
				"restart_required":  restartRequired,
				"counts_by_state":   states,
				"list_endpoint":     "/api/projects",
				"connection_status": "/api/projects/{project_id}/connection-status",
			},
		}})
	})
}
