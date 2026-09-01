package environment

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

const (
	MaxBrowserInteger  = uint64(9007199254740991)
	MaxAuthorityBytes  = 2 << 20
	MaxManifestBytes   = 1 << 20
	MaxBindingBytes    = 2 << 10
	MaxEnrollmentBytes = 8 << 10

	AuthorityContentType = "application/paperboat.environment.authority+cbor;v=1"
	BindingContentType   = "application/paperboat.environment.key-binding+cbor;v=1"
	ManifestContentType  = "application/paperboat.environment.scope-manifest+cbor;v=1"
	AbortContentType     = "application/paperboat.environment.authority-transition-abort+cbor;v=1"
)

var (
	ErrProtocolInvalid   = errors.New("environment E2EE document is invalid")
	ErrProtocolSignature = errors.New("environment E2EE signature is invalid")
	keyIDExpression      = regexp.MustCompile(`^(sigk|envk)_[A-Za-z0-9_-]{43}$`)
	operationExpression  = regexp.MustCompile(`^envop_[0-9a-f]{32}$`)
	identifierExpression = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

	canonicalEncoding cbor.EncMode
	strictDecoding    cbor.DecMode
)

func init() {
	var err error
	canonicalEncoding, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	strictDecoding, err = (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsAllowed,
		MaxNestedLevels:  16,
		MaxArrayElements: 2048,
		MaxMapPairs:      16,
		UTF8:             cbor.UTF8RejectInvalid,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

type Binding struct {
	ID                  string
	Raw                 []byte
	AccountID           string
	SubjectKind         int
	SubjectID           string
	SubjectGeneration   uint64
	KeyGeneration       uint64
	EndpointCertificate []byte
	SigningPublicKey    ed25519.PublicKey
	SigningKeyID        string
	signingKeyIDPresent bool
	RecipientPublicKey  [32]byte
	RecipientKeyID      string
	NotBefore           time.Time
	NotAfter            *time.Time
	Serial              uint64
}

func (b Binding) SubjectKindName() string {
	switch b.SubjectKind {
	case 1:
		return "manager_cli"
	case 2:
		return "manager_browser"
	case 3:
		return "host"
	case 4:
		return "recovery"
	default:
		return ""
	}
}

type Authority struct {
	ID        string
	Raw       []byte
	AccountID string
	// SignerKeyID is the account-root key named by the authority's COSE
	// protected header.  It is deliberately retained separately from the
	// manager/binding keys: the first authority is the ceremony that pins the
	// ENV verifier root, so persistence must pin this exact signer rather than
	// every currently-live account root.
	SignerKeyID string
	Generation  uint64
	PreviousID  string
	OperationID string
	Bindings    []Binding
	ResetScopes []ScopeRef
}

// VerificationRoots keeps the two account-root trust domains used while
// parsing ENV documents separate. Environment contains roots allowed to
// authenticate ENV COSE envelopes. Endpoint contains live account roots
// allowed to authenticate embedded endpoint certificates.
type VerificationRoots struct {
	Environment peeridentity.AccountRoot
	Endpoint    peeridentity.AccountRoot
}

type ScopeRef struct {
	Scope     string `json:"scope"`
	MachineID string `json:"machine_id,omitempty"`
}

const (
	// Scope reference keys are persisted in transition inventories. Keep the
	// scope kind in the key so a machine named "global" cannot alias the
	// global scope.
	scopeRefGlobalKey  = "g"
	scopeRefMachineKey = "m:"
)

func (s ScopeRef) Key() string {
	switch s.Scope {
	case ScopeGlobal:
		return scopeRefGlobalKey
	case ScopeMachine:
		return scopeRefMachineKey + s.MachineID
	default:
		return ""
	}
}

type RecipientWrap struct {
	Kind                 int
	SubjectID            string
	KeyGeneration        uint64
	KeyID                string
	EncapsulatedKey      []byte
	WrappedKeyCiphertext []byte
}

type Manifest struct {
	ID                  string
	Raw                 []byte
	SignerKeyID         string
	AccountID           string
	AuthorityGeneration uint64
	AuthorityID         string
	Scope               string
	MachineID           string
	ScopeState          string
	PreviousVersion     uint64
	Version             uint64
	KeyEpoch            uint64
	OperationID         string
	MutationKind        int
	ChangedNames        []string
	Names               []string
	CiphertextDigest    [32]byte
	Ciphertext          []byte
	Wraps               []RecipientWrap
}

type AbortAuthorization struct {
	Raw               []byte
	AccountID         string
	ActiveAuthorityID string
	TransitionID      string
	OperationID       string
}

func EncodeCanonical(value any) ([]byte, error) { return canonicalEncoding.Marshal(value) }

func DecodeCanonicalBase64URL(value string, max int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") || len(value) > (max*4/3)+4 {
		return nil, ErrProtocolInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > max || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, ErrProtocolInvalid
	}
	return raw, nil
}

func DocumentID(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func ParseAuthority(raw []byte, environmentRoots peeridentity.AccountRoot, endpointRoots ...peeridentity.AccountRoot) (Authority, error) {
	if len(raw) == 0 || len(raw) > MaxAuthorityBytes {
		return Authority{}, ErrProtocolInvalid
	}
	endpoints, err := endpointVerificationRoots(environmentRoots, endpointRoots)
	if err != nil {
		return Authority{}, err
	}
	rootKeys, err := rootKeyMap(environmentRoots)
	if err != nil {
		return Authority{}, err
	}
	if _, err := rootKeyMap(endpoints); err != nil {
		return Authority{}, err
	}
	body, signer, err := verifyCOSE(raw, AuthorityContentType, rootKeys)
	if err != nil {
		return Authority{}, err
	}
	fields, err := decodeArray(body, 8)
	if err != nil {
		return Authority{}, err
	}
	var domain string
	var version uint64
	var account string
	var generation uint64
	var operation []byte
	if decode(fields[0], &domain) != nil || domain != "paperboat.environment.authority" || decode(fields[1], &version) != nil || version != 1 || decode(fields[2], &account) != nil || !validIdentifier(account) || decode(fields[3], &generation) != nil || !validCounter(generation) || decode(fields[5], &operation) != nil || len(operation) != 16 {
		return Authority{}, ErrProtocolInvalid
	}
	previous, err := nullableDigest(fields[4])
	if err != nil {
		return Authority{}, err
	}
	var bindingBytes [][]byte
	if decode(fields[6], &bindingBytes) != nil || len(bindingBytes) < 2 || len(bindingBytes) > 545 {
		return Authority{}, ErrProtocolInvalid
	}
	bindings := make([]Binding, 0, len(bindingBytes))
	seenSubject := map[string]bool{}
	seenSigning := map[string]bool{}
	seenRecipient := map[string]bool{}
	recovery := 0
	managers, hosts := 0, 0
	for _, encoded := range bindingBytes {
		binding, parseErr := parseBinding(encoded, environmentRoots, endpoints)
		if parseErr != nil || binding.AccountID != account {
			return Authority{}, ErrProtocolInvalid
		}
		subjectKey := fmt.Sprintf("%d\x00%s", binding.SubjectKind, binding.SubjectID)
		if seenSubject[subjectKey] || seenRecipient[binding.RecipientKeyID] || (binding.SigningKeyID != "" && seenSigning[binding.SigningKeyID]) {
			return Authority{}, ErrProtocolInvalid
		}
		seenSubject[subjectKey], seenRecipient[binding.RecipientKeyID] = true, true
		if binding.SigningKeyID != "" {
			seenSigning[binding.SigningKeyID] = true
		}
		if binding.SubjectKind == 4 {
			recovery++
		}
		if binding.SubjectKind == 1 || binding.SubjectKind == 2 {
			managers++
		}
		if binding.SubjectKind == 3 {
			hosts++
		}
		bindings = append(bindings, binding)
	}
	if recovery != 1 || managers == 0 || managers > 32 || hosts > 512 || !bindingsSorted(bindings) {
		return Authority{}, ErrProtocolInvalid
	}
	var resetRaw []cbor.RawMessage
	if decode(fields[7], &resetRaw) != nil {
		return Authority{}, ErrProtocolInvalid
	}
	reset := make([]ScopeRef, 0, len(resetRaw))
	last := ""
	for _, item := range resetRaw {
		pair, pairErr := decodeArray(item, 2)
		if pairErr != nil {
			return Authority{}, ErrProtocolInvalid
		}
		var kind uint64
		if decode(pair[0], &kind) != nil || kind > 1 {
			return Authority{}, ErrProtocolInvalid
		}
		machine, machineErr := nullableString(pair[1])
		if machineErr != nil {
			return Authority{}, ErrProtocolInvalid
		}
		ref := ScopeRef{Scope: ScopeGlobal}
		if kind == 1 {
			if machine == "" || !validIdentifier(machine) {
				return Authority{}, ErrProtocolInvalid
			}
			ref.Scope, ref.MachineID = ScopeMachine, machine
		} else if machine != "" {
			return Authority{}, ErrProtocolInvalid
		}
		if ref.Key() <= last {
			return Authority{}, ErrProtocolInvalid
		}
		last = ref.Key()
		reset = append(reset, ref)
	}
	return Authority{ID: DocumentID(raw), Raw: slices.Clone(raw), AccountID: account, SignerKeyID: signer, Generation: generation, PreviousID: previous, OperationID: operationID(operation), Bindings: bindings, ResetScopes: reset}, nil
}

func ParseBinding(raw []byte, environmentRoots peeridentity.AccountRoot, endpointRoots ...peeridentity.AccountRoot) (Binding, error) {
	endpoints, err := endpointVerificationRoots(environmentRoots, endpointRoots)
	if err != nil {
		return Binding{}, err
	}
	return parseBinding(raw, environmentRoots, endpoints)
}

func parseBinding(raw []byte, environmentRoots, endpointRoots peeridentity.AccountRoot) (Binding, error) {
	if len(raw) == 0 || len(raw) > MaxBindingBytes {
		return Binding{}, ErrProtocolInvalid
	}
	rootKeys, err := rootKeyMap(environmentRoots)
	if err != nil {
		return Binding{}, err
	}
	endpointKeys, err := rootKeyMap(endpointRoots)
	if err != nil {
		return Binding{}, err
	}
	body, _, err := verifyCOSE(raw, BindingContentType, rootKeys)
	if err != nil {
		return Binding{}, err
	}
	fields, err := decodeArray(body, 15)
	if err != nil {
		return Binding{}, err
	}
	var domain, account, subjectID, signingID, recipientID string
	var version, subjectKind, subjectGen, keyGen, notBefore, serial uint64
	var endpoint, signing, recipient []byte
	if decode(fields[0], &domain) != nil || domain != "paperboat.environment.key-binding" || decode(fields[1], &version) != nil || version != 1 || decode(fields[2], &account) != nil || !validIdentifier(account) || decode(fields[3], &subjectKind) != nil || subjectKind < 1 || subjectKind > 4 || decode(fields[4], &subjectID) != nil || !validIdentifier(subjectID) || decode(fields[5], &subjectGen) != nil || !validCounter(subjectGen) || decode(fields[6], &keyGen) != nil || !validCounter(keyGen) {
		return Binding{}, ErrProtocolInvalid
	}
	endpoint, err = nullableBytes(fields[7])
	if err != nil {
		return Binding{}, err
	}
	signing, err = nullableBytes(fields[8])
	if err != nil {
		return Binding{}, err
	}
	signingID, err = nullableString(fields[9])
	if err != nil {
		return Binding{}, err
	}
	if decode(fields[10], &recipient) != nil || len(recipient) != 32 || decode(fields[11], &recipientID) != nil || !validKeyID(recipientID, "envk_", recipient) || decode(fields[12], &notBefore) != nil || !validCounter(notBefore) || decode(fields[14], &serial) != nil || !validCounter(serial) {
		return Binding{}, ErrProtocolInvalid
	}
	notAfterSeconds, err := nullableCounter(fields[13])
	if err != nil {
		return Binding{}, err
	}
	manager := subjectKind == 1 || subjectKind == 2
	if manager != (len(signing) == 32 && validKeyID(signingID, "sigk_", signing)) || (!manager && (len(signing) != 0 || signingID != "")) {
		return Binding{}, ErrProtocolInvalid
	}
	if (subjectKind == 1 || subjectKind == 3) != (len(endpoint) > 0) || ((subjectKind == 2 || subjectKind == 4) && len(endpoint) != 0) {
		return Binding{}, ErrProtocolInvalid
	}
	issued := time.Unix(int64(notBefore), 0).UTC()
	var notAfter *time.Time
	if notAfterSeconds != 0 {
		value := time.Unix(int64(notAfterSeconds), 0).UTC()
		if !value.After(issued) {
			return Binding{}, ErrProtocolInvalid
		}
		notAfter = &value
	}
	if notAfter != nil {
		return Binding{}, ErrProtocolInvalid
	}
	if subjectKind == 4 && subjectID != "environment_recovery" {
		return Binding{}, ErrProtocolInvalid
	}
	if len(endpoint) > 0 {
		role := peeridentity.RoleCLI
		if subjectKind == 3 {
			role = peeridentity.RoleMachine
		}
		expected := peeridentity.Expected{AccountID: account, Role: role, EndpointID: subjectID, Generation: subjectGen}
		verified := false
		for _, rootPublic := range endpointKeys {
			if _, verifyErr := peeridentity.Verify(endpoint, rootPublic, expected, issued); verifyErr == nil {
				verified = true
				break
			}
		}
		if !verified {
			return Binding{}, ErrProtocolInvalid
		}
	}
	var recipientKey [32]byte
	copy(recipientKey[:], recipient)
	return Binding{ID: DocumentID(raw), Raw: slices.Clone(raw), AccountID: account, SubjectKind: int(subjectKind), SubjectID: subjectID, SubjectGeneration: subjectGen, KeyGeneration: keyGen, EndpointCertificate: endpoint, SigningPublicKey: ed25519.PublicKey(slices.Clone(signing)), SigningKeyID: signingID, signingKeyIDPresent: !isCBORNull(fields[9]), RecipientPublicKey: recipientKey, RecipientKeyID: recipientID, NotBefore: issued, NotAfter: notAfter, Serial: serial}, nil
}

func endpointVerificationRoots(environmentRoots peeridentity.AccountRoot, endpointRoots []peeridentity.AccountRoot) (peeridentity.AccountRoot, error) {
	if len(endpointRoots) == 0 {
		// Preserve the parser's original standalone behavior. Service callers
		// always provide the live endpoint set explicitly.
		return environmentRoots, nil
	}
	if len(endpointRoots) != 1 {
		return peeridentity.AccountRoot{}, ErrProtocolInvalid
	}
	return endpointRoots[0], nil
}

func rootKeyMap(roots peeridentity.AccountRoot) (map[string]ed25519.PublicKey, error) {
	rootKeys := make(map[string]ed25519.PublicKey, len(roots.Keys))
	for _, root := range roots.Keys {
		if !validRootKeyID(root.KeyID, root.PublicKey) {
			return nil, ErrProtocolInvalid
		}
		rootKeys[root.KeyID] = root.PublicKey
	}
	return rootKeys, nil
}

func ParseManifest(raw []byte, authority Authority) (Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return Manifest{}, ErrProtocolInvalid
	}
	managerKeys := map[string]ed25519.PublicKey{}
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == 1 || binding.SubjectKind == 2 {
			managerKeys[binding.SigningKeyID] = binding.SigningPublicKey
		}
	}
	body, signer, err := verifyCOSE(raw, ManifestContentType, managerKeys)
	if err != nil {
		return Manifest{}, err
	}
	fields, err := decodeArray(body, 21)
	if err != nil {
		return Manifest{}, err
	}
	var domain, account string
	var wire, profile, authGen, kind, state, previous, version, epoch, mutation uint64
	var authID, operation, salt, nonce, cipherDigest, ciphertext []byte
	var changed, names []string
	var wrapsRaw []cbor.RawMessage
	checks := []error{decode(fields[0], &domain), decode(fields[1], &wire), decode(fields[2], &profile), decode(fields[3], &account), decode(fields[4], &authGen), decode(fields[5], &authID), decode(fields[6], &kind), decode(fields[8], &state), decode(fields[9], &previous), decode(fields[10], &version), decode(fields[11], &epoch), decode(fields[12], &operation), decode(fields[13], &salt), decode(fields[14], &nonce), decode(fields[15], &mutation), decode(fields[16], &changed), decode(fields[17], &names), decode(fields[18], &cipherDigest), decode(fields[19], &ciphertext), decode(fields[20], &wrapsRaw)}
	for _, check := range checks {
		if check != nil {
			return Manifest{}, ErrProtocolInvalid
		}
	}
	if domain != "paperboat.environment.scope-manifest" || wire != 1 || profile != 1 || account != authority.AccountID || authGen != authority.Generation || len(authID) != 32 || digestText(authID) != authority.ID || kind > 1 || state > 1 || previous > MaxBrowserInteger || !validCounter(version) || version != previous+1 || !validCounter(epoch) || len(operation) != 16 || len(salt) != 32 || len(nonce) != 12 || mutation > 5 || len(cipherDigest) != 32 || !validCiphertextLength(len(ciphertext)) || sha256.Sum256(ciphertext) != [32]byte(cipherDigest) || len(names) > MaxVariables || len(changed) > MaxVariables || !sortedUniqueNames(names) || !sortedUniqueNamesAllowEmpty(changed) {
		return Manifest{}, ErrProtocolInvalid
	}
	machine, err := nullableString(fields[7])
	if err != nil {
		return Manifest{}, err
	}
	scope, scopeState := ScopeGlobal, "active"
	if kind == 1 {
		scope = ScopeMachine
		if machine == "" || !validIdentifier(machine) {
			return Manifest{}, ErrProtocolInvalid
		}
		if state == 1 {
			scopeState = "retired"
		}
	} else if machine != "" || state != 0 {
		return Manifest{}, ErrProtocolInvalid
	}
	wraps := make([]RecipientWrap, 0, len(wrapsRaw))
	for _, encoded := range wrapsRaw {
		wrapFields, wrapErr := decodeArray(encoded, 6)
		if wrapErr != nil {
			return Manifest{}, ErrProtocolInvalid
		}
		var wrap RecipientWrap
		var wrapKind uint64
		if decode(wrapFields[0], &wrapKind) != nil || wrapKind < 1 || wrapKind > 3 || decode(wrapFields[1], &wrap.SubjectID) != nil || !validIdentifier(wrap.SubjectID) || decode(wrapFields[2], &wrap.KeyGeneration) != nil || !validCounter(wrap.KeyGeneration) || decode(wrapFields[3], &wrap.KeyID) != nil || !strings.HasPrefix(wrap.KeyID, "envk_") || !keyIDExpression.MatchString(wrap.KeyID) || decode(wrapFields[4], &wrap.EncapsulatedKey) != nil || len(wrap.EncapsulatedKey) != 32 || decode(wrapFields[5], &wrap.WrappedKeyCiphertext) != nil || len(wrap.WrappedKeyCiphertext) != 48 {
			return Manifest{}, ErrProtocolInvalid
		}
		wrap.Kind = int(wrapKind)
		wraps = append(wraps, wrap)
	}
	if (scope == ScopeGlobal && len(wraps) > 545) || (scope == ScopeMachine && len(wraps) > 34) {
		return Manifest{}, ErrProtocolInvalid
	}
	if !wrapsSorted(wraps) || !exactRecipientRoster(scope, machine, scopeState, wraps, authority.Bindings) {
		return Manifest{}, ErrProtocolInvalid
	}
	return Manifest{ID: DocumentID(raw), Raw: slices.Clone(raw), SignerKeyID: signer, AccountID: account, AuthorityGeneration: authGen, AuthorityID: authority.ID, Scope: scope, MachineID: machine, ScopeState: scopeState, PreviousVersion: previous, Version: version, KeyEpoch: epoch, OperationID: operationID(operation), MutationKind: int(mutation), ChangedNames: changed, Names: names, CiphertextDigest: sha256.Sum256(ciphertext), Ciphertext: ciphertext, Wraps: wraps}, nil
}

func ParseAbort(raw []byte, roots peeridentity.AccountRoot) (AbortAuthorization, error) {
	if len(raw) == 0 || len(raw) > MaxBindingBytes {
		return AbortAuthorization{}, ErrProtocolInvalid
	}
	keys := map[string]ed25519.PublicKey{}
	for _, root := range roots.Keys {
		keys[root.KeyID] = root.PublicKey
	}
	body, _, err := verifyCOSE(raw, AbortContentType, keys)
	if err != nil {
		return AbortAuthorization{}, err
	}
	fields, err := decodeArray(body, 6)
	if err != nil {
		return AbortAuthorization{}, err
	}
	var domain, account string
	var version uint64
	var active, transition, operation []byte
	if decode(fields[0], &domain) != nil || domain != "paperboat.environment.authority-transition-abort" || decode(fields[1], &version) != nil || version != 1 || decode(fields[2], &account) != nil || !validIdentifier(account) || decode(fields[3], &active) != nil || len(active) != 32 || decode(fields[4], &transition) != nil || len(transition) != 32 || decode(fields[5], &operation) != nil || len(operation) != 16 {
		return AbortAuthorization{}, ErrProtocolInvalid
	}
	return AbortAuthorization{Raw: slices.Clone(raw), AccountID: account, ActiveAuthorityID: digestText(active), TransitionID: digestText(transition), OperationID: operationID(operation)}, nil
}

type EnrollmentCanonicalInput struct {
	AccountID, OperationID           string
	SubjectKind                      int
	SubjectID                        string
	SubjectGeneration, KeyGeneration uint64
	EndpointCertificate              []byte
	SigningPublic                    []byte
	SigningKeyID                     string
	RecipientPublic                  []byte
	RecipientKeyID                   string
	ExpiresAt                        time.Time
}

func CanonicalEnrollment(input EnrollmentCanonicalInput) ([]byte, [32]byte, string, error) {
	var zero [32]byte
	op, err := operationBytes(input.OperationID)
	if err != nil || !validIdentifier(input.AccountID) || input.SubjectKind < 1 || input.SubjectKind > 3 || !validIdentifier(input.SubjectID) || !validCounter(input.SubjectGeneration) || !validCounter(input.KeyGeneration) || len(input.RecipientPublic) != 32 || !validKeyID(input.RecipientKeyID, "envk_", input.RecipientPublic) || input.ExpiresAt.IsZero() || input.ExpiresAt.Unix() <= 0 || uint64(input.ExpiresAt.Unix()) > MaxBrowserInteger || !time.Unix(input.ExpiresAt.Unix(), 0).UTC().Equal(input.ExpiresAt.UTC()) {
		return nil, zero, "", ErrProtocolInvalid
	}
	manager := input.SubjectKind == 1 || input.SubjectKind == 2
	if manager != (len(input.SigningPublic) == 32 && validKeyID(input.SigningKeyID, "sigk_", input.SigningPublic)) || (!manager && (len(input.SigningPublic) != 0 || input.SigningKeyID != "")) {
		return nil, zero, "", ErrProtocolInvalid
	}
	if (input.SubjectKind == 1 || input.SubjectKind == 3) != (len(input.EndpointCertificate) > 0) || (input.SubjectKind == 2 && len(input.EndpointCertificate) != 0) {
		return nil, zero, "", ErrProtocolInvalid
	}
	var endpoint any = nil
	if len(input.EndpointCertificate) > 0 {
		endpoint = input.EndpointCertificate
	}
	var signing any = nil
	var signingID any = nil
	if len(input.SigningPublic) > 0 {
		signing = input.SigningPublic
		signingID = input.SigningKeyID
	}
	encoded, err := EncodeCanonical([]any{"paperboat.environment.enrollment-request", uint64(1), input.AccountID, op, uint64(input.SubjectKind), input.SubjectID, input.SubjectGeneration, input.KeyGeneration, endpoint, signing, signingID, input.RecipientPublic, input.RecipientKeyID, nil, uint64(input.ExpiresAt.Unix())})
	if err != nil || len(encoded) > MaxEnrollmentBytes {
		return nil, zero, "", ErrProtocolInvalid
	}
	digest := sha256.Sum256(encoded)
	sasInput, _ := EncodeCanonical([]any{"paperboat.environment.enrollment-safety-code", uint64(1), encoded})
	sasDigest := sha256.Sum256(sasInput)
	raw := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sasDigest[:10]))
	sas := raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16]
	return encoded, digest, sas, nil
}

// ParseCanonicalEnrollment validates and decodes the exact enrollment request
// bytes journaled by the server. Re-encoding the decoded fields is deliberate:
// it rejects alternate representations such as empty byte/text values where
// the enrollment contract requires null.
func ParseCanonicalEnrollment(raw []byte) (EnrollmentCanonicalInput, error) {
	if len(raw) == 0 || len(raw) > MaxEnrollmentBytes || !canonical(raw) {
		return EnrollmentCanonicalInput{}, ErrProtocolInvalid
	}
	fields, err := decodeArray(raw, 15)
	if err != nil {
		return EnrollmentCanonicalInput{}, err
	}
	var domain, account string
	var version, subjectKind, subjectGeneration, keyGeneration, requestExpiresAt uint64
	var operation, recipient []byte
	if decode(fields[0], &domain) != nil || domain != "paperboat.environment.enrollment-request" ||
		decode(fields[1], &version) != nil || version != 1 ||
		decode(fields[2], &account) != nil || !validIdentifier(account) ||
		decode(fields[3], &operation) != nil || len(operation) != 16 ||
		decode(fields[4], &subjectKind) != nil || subjectKind < 1 || subjectKind > 3 ||
		decode(fields[6], &subjectGeneration) != nil || !validCounter(subjectGeneration) ||
		decode(fields[7], &keyGeneration) != nil || !validCounter(keyGeneration) {
		return EnrollmentCanonicalInput{}, ErrProtocolInvalid
	}
	var subjectID string
	if decode(fields[5], &subjectID) != nil || !validIdentifier(subjectID) {
		return EnrollmentCanonicalInput{}, ErrProtocolInvalid
	}
	endpoint, err := nullableBytes(fields[8])
	if err != nil {
		return EnrollmentCanonicalInput{}, err
	}
	signing, err := nullableBytes(fields[9])
	if err != nil {
		return EnrollmentCanonicalInput{}, err
	}
	signingID, err := nullableString(fields[10])
	if err != nil {
		return EnrollmentCanonicalInput{}, err
	}
	if decode(fields[11], &recipient) != nil || len(recipient) != 32 {
		return EnrollmentCanonicalInput{}, ErrProtocolInvalid
	}
	var recipientID string
	if decode(fields[12], &recipientID) != nil || !validKeyID(recipientID, "envk_", recipient) {
		return EnrollmentCanonicalInput{}, ErrProtocolInvalid
	}
	// Profile 1 has no requested binding expiry. It is distinct from the
	// five-minute request receipt deadline in the final field.
	if !isCBORNull(fields[13]) || decode(fields[14], &requestExpiresAt) != nil || !validCounter(requestExpiresAt) {
		return EnrollmentCanonicalInput{}, ErrProtocolInvalid
	}
	input := EnrollmentCanonicalInput{
		AccountID:           account,
		OperationID:         operationID(operation),
		SubjectKind:         int(subjectKind),
		SubjectID:           subjectID,
		SubjectGeneration:   subjectGeneration,
		KeyGeneration:       keyGeneration,
		EndpointCertificate: endpoint,
		SigningPublic:       signing,
		SigningKeyID:        signingID,
		RecipientPublic:     recipient,
		RecipientKeyID:      recipientID,
		ExpiresAt:           time.Unix(int64(requestExpiresAt), 0).UTC(),
	}
	encoded, _, _, err := CanonicalEnrollment(input)
	if err != nil || !bytes.Equal(encoded, raw) {
		return EnrollmentCanonicalInput{}, ErrProtocolInvalid
	}
	return input, nil
}

func EnrollmentSigningBytes(canonical []byte) []byte {
	out, _ := EncodeCanonical([]any{"paperboat.environment.enrollment-request-signature", uint64(1), canonical})
	return out
}

func SealEnrollmentChallenge(accountID, requestID, operationID, recipientKeyID string, recipientPublic, requestDigest []byte) (envelope, expectedProof []byte, err error) {
	operation, err := operationBytes(operationID)
	if err != nil || len(recipientPublic) != 32 || len(requestDigest) != 32 {
		return nil, nil, ErrProtocolInvalid
	}
	info, _ := EncodeCanonical([]any{"paperboat.environment.enrollment-challenge-info", uint64(1), uint64(1), accountID, requestID, operation, recipientKeyID})
	aad, _ := EncodeCanonical([]any{"paperboat.environment.enrollment-challenge-aad", uint64(1), requestDigest})
	var challenge [32]byte
	if _, err = rand.Read(challenge[:]); err != nil {
		return nil, nil, err
	}
	x25519Public, err := ecdh.X25519().NewPublicKey(recipientPublic)
	if err != nil {
		return nil, nil, ErrProtocolInvalid
	}
	public, err := hpke.NewDHKEMPublicKey(x25519Public)
	if err != nil {
		return nil, nil, ErrProtocolInvalid
	}
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := sender.Seal(aad, challenge[:])
	if err != nil {
		return nil, nil, err
	}
	proofInput, _ := EncodeCanonical([]any{"paperboat.environment.enrollment-proof", uint64(1), accountID, requestID, operation, requestDigest, challenge[:]})
	proof := sha256.Sum256(proofInput)
	return append(enc, sealed...), proof[:], nil
}

func verifyCOSE(raw []byte, contentType string, keys map[string]ed25519.PublicKey) ([]byte, string, error) {
	if !canonical(raw) {
		return nil, "", ErrProtocolInvalid
	}
	var tag cbor.RawTag
	if strictDecoding.Unmarshal(raw, &tag) != nil || tag.Number != 18 {
		return nil, "", ErrProtocolInvalid
	}
	parts, err := decodeArray(tag.Content, 4)
	if err != nil {
		return nil, "", err
	}
	var protected, payload, signature []byte
	var unprotected map[any]any
	if decode(parts[0], &protected) != nil || decode(parts[1], &unprotected) != nil || len(unprotected) != 0 || decode(parts[2], &payload) != nil || decode(parts[3], &signature) != nil || len(signature) != ed25519.SignatureSize {
		return nil, "", ErrProtocolInvalid
	}
	if !canonical(protected) || !canonical(payload) {
		return nil, "", ErrProtocolInvalid
	}
	var header map[int64]cbor.RawMessage
	if strictDecoding.Unmarshal(protected, &header) != nil || len(header) != 3 {
		return nil, "", ErrProtocolInvalid
	}
	var alg int64
	var typ string
	var kid []byte
	if decode(header[1], &alg) != nil || alg != -8 || decode(header[3], &typ) != nil || typ != contentType || decode(header[4], &kid) != nil {
		return nil, "", ErrProtocolInvalid
	}
	signer := string(kid)
	key, ok := keys[signer]
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, "", ErrProtocolSignature
	}
	toSign, _ := EncodeCanonical([]any{"Signature1", protected, []byte{}, payload})
	if !ed25519.Verify(key, toSign, signature) {
		return nil, "", ErrProtocolSignature
	}
	return payload, signer, nil
}

func canonical(raw []byte) bool {
	var value any
	if strictDecoding.Unmarshal(raw, &value) != nil {
		return false
	}
	encoded, err := canonicalEncoding.Marshal(value)
	return err == nil && bytes.Equal(encoded, raw)
}
func decode(raw cbor.RawMessage, target any) error { return strictDecoding.Unmarshal(raw, target) }
func decodeArray(raw []byte, count int) ([]cbor.RawMessage, error) {
	var fields []cbor.RawMessage
	if strictDecoding.Unmarshal(raw, &fields) != nil || len(fields) != count {
		return nil, ErrProtocolInvalid
	}
	return fields, nil
}
func isCBORNull(raw cbor.RawMessage) bool { return bytes.Equal(raw, []byte{0xf6}) }
func nullableBytes(raw cbor.RawMessage) ([]byte, error) {
	if isCBORNull(raw) {
		return nil, nil
	}
	var value []byte
	if decode(raw, &value) != nil {
		return nil, ErrProtocolInvalid
	}
	return value, nil
}
func nullableString(raw cbor.RawMessage) (string, error) {
	if isCBORNull(raw) {
		return "", nil
	}
	var value string
	if decode(raw, &value) != nil {
		return "", ErrProtocolInvalid
	}
	return value, nil
}
func nullableCounter(raw cbor.RawMessage) (uint64, error) {
	if isCBORNull(raw) {
		return 0, nil
	}
	var value uint64
	if decode(raw, &value) != nil || !validCounter(value) {
		return 0, ErrProtocolInvalid
	}
	return value, nil
}
func nullableDigest(raw cbor.RawMessage) (string, error) {
	value, err := nullableBytes(raw)
	if err != nil || (len(value) != 0 && len(value) != 32) {
		return "", ErrProtocolInvalid
	}
	if len(value) == 0 {
		return "", nil
	}
	return digestText(value), nil
}
func validCounter(value uint64) bool { return value > 0 && value <= MaxBrowserInteger }
func validCiphertextLength(length int) bool {
	for _, bucket := range []int{1024, 4096, 16384, 65536, 262144, 524288} {
		if length == bucket+16 {
			return true
		}
	}
	return false
}
func validIdentifier(value string) bool {
	return len(value) > 0 && len(value) <= 128 && identifierExpression.MatchString(value)
}
func digestText(value []byte) string { return "sha256:" + hex.EncodeToString(value) }
func operationID(raw []byte) string  { return "envop_" + hex.EncodeToString(raw) }
func operationBytes(value string) ([]byte, error) {
	if !operationExpression.MatchString(value) {
		return nil, ErrProtocolInvalid
	}
	return hex.DecodeString(strings.TrimPrefix(value, "envop_"))
}
func validKeyID(id, prefix string, public []byte) bool {
	if !strings.HasPrefix(id, prefix) || !keyIDExpression.MatchString(id) || len(public) != 32 {
		return false
	}
	crv := "X25519"
	if prefix == "sigk_" {
		crv = "Ed25519"
	}
	jwk := []byte(`{"crv":"` + crv + `","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(public) + `"}`)
	digest := sha256.Sum256(jwk)
	return id == prefix+base64.RawURLEncoding.EncodeToString(digest[:])
}
func validRootKeyID(id string, public []byte) bool {
	digest := sha256.Sum256(public)
	return len(public) == ed25519.PublicKeySize && id == "aek_"+hex.EncodeToString(digest[:])
}
func bindingsSorted(values []Binding) bool {
	for i := 1; i < len(values); i++ {
		a, b := values[i-1], values[i]
		if a.SubjectKind > b.SubjectKind || (a.SubjectKind == b.SubjectKind && (a.SubjectID > b.SubjectID || (a.SubjectID == b.SubjectID && (a.KeyGeneration > b.KeyGeneration || (a.KeyGeneration == b.KeyGeneration && a.ID >= b.ID))))) {
			return false
		}
	}
	return true
}
func wrapsSorted(values []RecipientWrap) bool {
	for i := 1; i < len(values); i++ {
		a, b := values[i-1], values[i]
		if a.Kind > b.Kind || (a.Kind == b.Kind && (a.SubjectID > b.SubjectID || (a.SubjectID == b.SubjectID && (a.KeyGeneration > b.KeyGeneration || (a.KeyGeneration == b.KeyGeneration && a.KeyID >= b.KeyID))))) {
			return false
		}
	}
	return true
}
func sortedUniqueNames(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for i, v := range values {
		if ValidateName(v) != nil || (i > 0 && values[i-1] >= v) {
			return false
		}
	}
	return true
}
func sortedUniqueNamesAllowEmpty(values []string) bool { return sortedUniqueNames(values) }
func exactRecipientRoster(scope, machine, state string, wraps []RecipientWrap, bindings []Binding) bool {
	expected := make([]string, 0, len(bindings))
	for _, b := range bindings {
		kind := 0
		switch b.SubjectKind {
		case 1, 2:
			kind = 1
		case 3:
			kind = 2
		case 4:
			kind = 3
		}
		include := kind == 1 || kind == 3 || (kind == 2 && scope == ScopeGlobal) || (kind == 2 && scope == ScopeMachine && state == "active" && b.SubjectID == machine)
		if include {
			expected = append(expected, fmt.Sprintf("%d\x00%s\x00%020d\x00%s", kind, b.SubjectID, b.KeyGeneration, b.RecipientKeyID))
		}
	}
	actual := make([]string, 0, len(wraps))
	for _, w := range wraps {
		actual = append(actual, fmt.Sprintf("%d\x00%s\x00%020d\x00%s", w.Kind, w.SubjectID, w.KeyGeneration, w.KeyID))
	}
	sort.Strings(expected)
	sort.Strings(actual)
	return slices.Equal(expected, actual)
}
