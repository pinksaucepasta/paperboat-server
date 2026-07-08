package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

func projectsCreate(service *projects.Service) http.HandlerFunc {
	type request struct {
		Name            string   `json:"name"`
		RepositoryURL   string   `json:"repository_url"`
		DefaultBranch   string   `json:"default_branch"`
		StorageGB       int      `json:"storage_gb"`
		MachineTypeCode string   `json:"machine_type_code"`
		RegionCode      string   `json:"region_code"`
		PresetCodes     []string `json:"preset_codes"`
		IdleTimeoutCode string   `json:"idle_timeout_code"`
		SetupScript     string   `json:"setup_script"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		project, existed, err := service.Create(r.Context(), projects.CreateInput{
			UserID:          p.User.ID,
			IdempotencyKey:  r.Header.Get("Idempotency-Key"),
			Name:            body.Name,
			RepositoryURL:   body.RepositoryURL,
			DefaultBranch:   body.DefaultBranch,
			StorageGB:       body.StorageGB,
			MachineTypeCode: body.MachineTypeCode,
			RegionCode:      body.RegionCode,
			PresetCodes:     body.PresetCodes,
			IdleTimeoutCode: body.IdleTimeoutCode,
			SetupScript:     body.SetupScript,
		})
		if writeProjectError(w, r, err) {
			return
		}
		status := http.StatusCreated
		if existed {
			status = http.StatusOK
		}
		writeJSON(w, status, SuccessResponse{Data: project})
	}
}

func projectsKeepAlive(service *projects.Service) http.HandlerFunc {
	type request struct {
		DurationSeconds int  `json:"duration_seconds"`
		Clear           bool `json:"clear"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		if !body.Clear && body.DurationSeconds <= 0 {
			writeError(w, r, http.StatusBadRequest, "invalid_keep_alive", "Keep-alive duration must be positive unless clear is true.")
			return
		}
		duration := time.Duration(body.DurationSeconds) * time.Second
		if body.Clear {
			duration = 0
		}
		project, until, err := service.SetKeepAlive(r.Context(), p.User.ID, r.PathValue("project_id"), duration)
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
			"project":          project,
			"keep_alive_until": until,
		}})
	}
}

func projectsActivity(service *projects.Service) http.HandlerFunc {
	type request struct {
		Source     string         `json:"source"`
		ObservedAt *time.Time     `json:"observed_at"`
		Metadata   map[string]any `json:"metadata"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		var observedAt time.Time
		if body.ObservedAt != nil {
			observedAt = body.ObservedAt.UTC()
		}
		project, err := service.RecordClientActivity(r.Context(), projects.ActivityInput{
			UserID:     p.User.ID,
			ProjectID:  r.PathValue("project_id"),
			Source:     body.Source,
			ObservedAt: observedAt,
			Metadata:   body.Metadata,
		})
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: map[string]any{
			"accepted": true,
			"project":  project,
		}})
	}
}

func projectsList(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		items, err := service.List(r.Context(), p.User.ID)
		if writeProjectError(w, r, err) {
			return
		}
		query, ok := parseProjectListQuery(w, r)
		if !ok {
			return
		}
		items = filterProjects(items, query)
		sortProjects(items, query)
		total := len(items)
		end := query.Offset + query.Limit
		if query.Offset > total {
			items = []projects.Project{}
		} else {
			if end > total {
				end = total
			}
			items = items[query.Offset:end]
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
			"items": items,
			"pagination": map[string]any{
				"limit":       query.Limit,
				"offset":      query.Offset,
				"total":       total,
				"next_offset": nextOffset(query.Offset, query.Limit, total),
			},
			"filters": map[string]any{
				"state": query.State,
			},
			"sort": query.Sort,
		}})
	}
}

func projectsGet(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Get(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: project})
	}
}

func projectsUpdate(service *projects.Service) http.HandlerFunc {
	type request struct {
		Version         *int64    `json:"version"`
		StorageGB       *int      `json:"storage_gb"`
		MachineTypeCode *string   `json:"machine_type_code"`
		RegionCode      *string   `json:"region_code"`
		PresetCodes     *[]string `json:"preset_codes"`
		IdleTimeoutCode *string   `json:"idle_timeout_code"`
		SetupScript     *string   `json:"setup_script"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "Request body must be valid JSON.")
			return
		}
		expectedVersion, ok := projectExpectedVersion(w, r, body.Version)
		if !ok {
			return
		}
		project, err := service.Update(r.Context(), projects.UpdateInput{
			UserID:          p.User.ID,
			ProjectID:       r.PathValue("project_id"),
			ExpectedVersion: expectedVersion,
			StorageGB:       body.StorageGB,
			MachineTypeCode: body.MachineTypeCode,
			RegionCode:      body.RegionCode,
			PresetCodes:     body.PresetCodes,
			IdleTimeoutCode: body.IdleTimeoutCode,
			SetupScript:     body.SetupScript,
		})
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: project})
	}
}

func projectsDelete(service *projects.Service, access *agentunnel.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Delete(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		if access != nil {
			if err := access.RevokeProjectSessions(r.Context(), project.ID, "project_delete"); err != nil {
				writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
				return
			}
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsStart(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Start(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsStop(service *projects.Service, access *agentunnel.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Stop(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		if access != nil {
			if err := access.RevokeProjectSessions(r.Context(), project.ID, "machine_stop"); err != nil {
				writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
				return
			}
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsRestart(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		project, err := service.Restart(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: project})
	}
}

func projectsEvents(service *projects.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		events, err := service.Events(r.Context(), p.User.ID, r.PathValue("project_id"))
		if writeProjectError(w, r, err) {
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: events})
	}
}

func writeProjectError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, projects.ErrIdempotencyKeyRequired):
		writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required.")
	case errors.Is(err, projects.ErrIdempotencyConflict):
		writeError(w, r, http.StatusConflict, "idempotency_key_conflict", "Idempotency-Key conflicts with an existing project request.")
	case errors.Is(err, projects.ErrVersionRequired):
		writeError(w, r, http.StatusPreconditionRequired, "version_required", "Project update requires If-Match or a version field.")
	case errors.Is(err, projects.ErrVersionConflict):
		writeError(w, r, http.StatusPreconditionFailed, "version_conflict", "Project version does not match the current project.")
	case errors.Is(err, projects.ErrInvalidRepositoryURL):
		writeError(w, r, http.StatusBadRequest, "invalid_repository_url", "Repository URL must be an HTTPS git repository URL.")
	case errors.Is(err, projects.ErrInvalidStorage):
		writeError(w, r, http.StatusBadRequest, "invalid_storage", "Storage allocation must be positive.")
	case errors.Is(err, projects.ErrInvalidSetupScript):
		writeError(w, r, http.StatusBadRequest, "setup_script_too_large", "Setup script exceeds the configured size limit.")
	case errors.Is(err, projects.ErrCatalogUnavailable):
		writeError(w, r, http.StatusBadRequest, "catalog_unavailable", "One or more selected catalog entries are unavailable.")
	case errors.Is(err, projects.ErrInsufficientStorage), errors.Is(err, metering.ErrInsufficientStorage):
		writeError(w, r, http.StatusConflict, "insufficient_storage", "Project storage allocation exceeds available storage.")
	case errors.Is(err, projects.ErrInsufficientCredits):
		writeError(w, r, http.StatusConflict, "credits_exhausted", "Credits are too low to start this project.")
	case errors.Is(err, projects.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "project_not_found", "Project was not found.")
	case errors.Is(err, projects.ErrDeleted):
		writeError(w, r, http.StatusConflict, "project_deleted", "Deleted projects cannot be changed.")
	case errors.Is(err, projects.ErrInvalidState):
		writeError(w, r, http.StatusConflict, "invalid_project_state", "Project state does not allow this operation.")
	case errors.Is(err, projects.ErrInvalidKeepAlive):
		writeError(w, r, http.StatusBadRequest, "invalid_keep_alive", "Keep-alive duration is outside the configured bounds.")
	case errors.Is(err, projects.ErrInvalidActivitySource):
		writeError(w, r, http.StatusBadRequest, "invalid_activity_source", "Activity source is not accepted for this endpoint.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
	return true
}

type projectListQuery struct {
	Limit  int
	Offset int
	State  string
	Sort   string
}

func parseProjectListQuery(w http.ResponseWriter, r *http.Request) (projectListQuery, bool) {
	q := r.URL.Query()
	out := projectListQuery{Limit: 50, Sort: "-created_at"}
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > 200 {
			writeError(w, r, http.StatusBadRequest, "invalid_pagination", "limit must be between 1 and 200.")
			return projectListQuery{}, false
		}
		out.Limit = n
	}
	if raw := strings.TrimSpace(q.Get("offset")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, r, http.StatusBadRequest, "invalid_pagination", "offset must be nonnegative.")
			return projectListQuery{}, false
		}
		out.Offset = n
	}
	out.State = strings.TrimSpace(q.Get("state"))
	if raw := strings.TrimSpace(q.Get("sort")); raw != "" {
		switch raw {
		case "created_at", "-created_at", "updated_at", "-updated_at", "name", "-name", "state", "-state":
			out.Sort = raw
		default:
			writeError(w, r, http.StatusBadRequest, "invalid_sort", "sort must be one of created_at, updated_at, name, or state with optional '-' prefix.")
			return projectListQuery{}, false
		}
	}
	return out, true
}

func filterProjects(items []projects.Project, query projectListQuery) []projects.Project {
	if query.State == "" {
		return items
	}
	out := items[:0]
	for _, project := range items {
		if project.State == query.State {
			out = append(out, project)
		}
	}
	return out
}

func sortProjects(items []projects.Project, query projectListQuery) {
	desc := strings.HasPrefix(query.Sort, "-")
	field := strings.TrimPrefix(query.Sort, "-")
	sort.SliceStable(items, func(i, j int) bool {
		compare := 0
		switch field {
		case "name":
			compare = strings.Compare(strings.ToLower(items[i].Name), strings.ToLower(items[j].Name))
		case "state":
			compare = strings.Compare(items[i].State, items[j].State)
		case "updated_at":
			compare = compareTime(items[i].UpdatedAt, items[j].UpdatedAt)
		default:
			compare = compareTime(items[i].CreatedAt, items[j].CreatedAt)
		}
		if compare == 0 {
			return false
		}
		if desc {
			return compare > 0
		}
		return compare < 0
	})
}

func compareTime(a, b time.Time) int {
	switch {
	case a.Before(b):
		return -1
	case a.After(b):
		return 1
	default:
		return 0
	}
}

func nextOffset(offset, limit, total int) any {
	next := offset + limit
	if next >= total {
		return nil
	}
	return next
}

func projectExpectedVersion(w http.ResponseWriter, r *http.Request, bodyVersion *int64) (*int64, bool) {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if raw == "" {
		if bodyVersion == nil {
			writeProjectError(w, r, projects.ErrVersionRequired)
			return nil, false
		}
		return bodyVersion, true
	}
	raw = strings.Trim(raw, `"`)
	if strings.HasPrefix(raw, "project-version-") {
		raw = strings.TrimPrefix(raw, "project-version-")
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_version", "If-Match must contain a project version.")
		return nil, false
	}
	return &n, true
}
