package httpapi

import (
	"context"
	"net/http"

	"github.com/pinksaucepasta/paperboat-server/internal/environment"
)

type environmentVaultHostsAPI interface {
	RegisterVaultHostKey(context.Context, string, string, environment.VaultHostKeyRequest) (environment.VaultProjectionBundle, error)
	GetVaultHost(context.Context, string, string) (environment.VaultHostState, error)
	ProvisionVaultHost(context.Context, string, string, environment.VaultHostProvision) (environment.VaultProjectionBundle, error)
}

func registerEnvironmentVaultHostRoutes(mux *http.ServeMux, service environmentVaultHostsAPI, verifier machineEndpointProofVerifier, read, write func(http.Handler) http.Handler) {
	forbidden := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		writeError(w, r, http.StatusUnauthorized, "machine_identity_required", "A signed machine identity request is required.")
	})
	register := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := r.Context().Value(environmentMachinePrincipalKey{}).(environmentMachinePrincipal)
		if !ok || p.MachineID != r.PathValue("machine_id") {
			writeError(w, r, http.StatusForbidden, "forbidden", "The machine identity does not authorize this resource.")
			return
		}
		limitEnvironmentJSON(w, r, 2048)
		var req environment.VaultHostKeyRequest
		if !decodeStrictJSON(w, r, &req) {
			return
		}
		if req.OperationID != p.OperationID {
			writeEnvironmentError(w, r, environment.ErrProtocolInvalid)
			return
		}
		out, err := service.RegisterVaultHostKey(r.Context(), p.AccountID, p.MachineID, req)
		writeVaultScopeResult(w, r, out, err)
	})
	mux.Handle("POST /v1/environment/hosts/{machine_id}/key", environmentEnrollmentMachineOrHuman(verifier, forbidden, register))
	mux.Handle("GET /v1/environment/hosts/{machine_id}", read(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := vaultScopePrincipal(w, r)
		if !ok {
			return
		}
		out, err := service.GetVaultHost(r.Context(), account, r.PathValue("machine_id"))
		writeVaultScopeResult(w, r, out, err)
	})))
	mux.Handle("PUT /v1/environment/hosts/{machine_id}", write(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := vaultScopePrincipal(w, r)
		if !ok {
			return
		}
		limitEnvironmentJSON(w, r, 512<<10)
		var req environment.VaultHostProvision
		if !decodeStrictJSON(w, r, &req) {
			return
		}
		out, err := service.ProvisionVaultHost(r.Context(), account, r.PathValue("machine_id"), req)
		writeVaultScopeResult(w, r, out, err)
	})))
}
