package mattervault

// Per-interaction-group Read/Write permissions for member-tied API keys.
//
// A member-tied API key is a delegate holding a ProxyType::Scoped(ScopeSet)
// proxy on the account of the member who minted it, and everything it does it
// does as that member. The runtime maps every tenant-facing call to the set it
// requires and admits the call iff the key's set covers it.
//
// This is a wire contract, mirrored from matter-node's common/src/scopes.rs and
// pinned across languages by testvectors/scope_bits.json and
// testvectors/required_scopes.json. A ScopeSet is a bare u32 whose bit for
// (scope, access) is scope*2 + access. Both vocabularies are append-only: a new
// group takes the next index and the next two bits, and nothing already assigned
// ever moves.
//
// Ported rather than reached through cgo on purpose. A scope set is not
// cryptography, so it does not belong behind the C ABI; and the two
// argument-sensitive rows below must read call arguments as Go values, before
// anything is SCALE-encoded, which could not cross that boundary without
// shipping the whole argument tree with them.

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// Scope is an interaction group a key may be permissioned for. The value is the
// bit-pair index and is append-only.
type Scope uint8

// The ten scoped interaction groups, in bit-pair order.
const (
	ScopeDeployments Scope = iota
	ScopeCollaborations
	ScopeSecrets
	ScopeVolumes
	ScopeDatasets
	ScopeNetworking
	ScopeResources
	ScopeOrganization
	ScopeBilling
	ScopeCommunities
)

// Access is the half of a scope a key is granted. Neither implies the other.
type Access uint8

// The two halves of a scope.
const (
	AccessRead Access = iota
	AccessWrite
)

// scopeNames is indexed by Scope. One table, so rendering and parsing cannot
// disagree about a spelling.
var scopeNames = [...]string{
	"deployments",
	"collaborations",
	"secrets",
	"volumes",
	"datasets",
	"networking",
	"resources",
	"organization",
	"billing",
	"communities",
}

// emptyScopeText is how an empty set renders, and one of the two spellings that
// parse back to it.
const emptyScopeText = "(none)"

// AllScopes lists every defined scope, in index order.
var AllScopes = func() []Scope {
	all := make([]Scope, len(scopeNames))
	for i := range scopeNames {
		all[i] = Scope(i)
	}
	return all
}()

// Name is the lowercase wire name, as ScopeSet's String and ParseScopeSet use it.
func (s Scope) Name() string {
	if int(s) >= len(scopeNames) {
		return fmt.Sprintf("scope(%d)", uint8(s))
	}
	return scopeNames[s]
}

func scopeBit(scope Scope, access Access) uint32 {
	return 1 << (uint32(scope)*2 + uint32(access))
}

// ScopeSet is a set of (scope, access) grants, as a bare u32 bitmask.
//
// A value type: every combinator returns a new set, so one handed to a client
// cannot be widened behind its back.
type ScopeSet struct{ bits uint32 }

// EmptyScopeSet grants nothing.
func EmptyScopeSet() ScopeSet { return ScopeSet{} }

// AllScopeSet holds every defined (scope, access) bit.
func AllScopeSet() ScopeSet { return ScopeSet{bits: (1 << (uint32(len(scopeNames)) * 2)) - 1} }

// ScopeSetFromBits builds a set from raw bits — the wire form. Validate with
// IsValid before trusting it.
func ScopeSetFromBits(bits uint32) ScopeSet { return ScopeSet{bits: bits} }

// SingleScope is the set holding exactly (scope, access).
func SingleScope(scope Scope, access Access) ScopeSet {
	return ScopeSet{bits: scopeBit(scope, access)}
}

// CoveringScopes is both halves of every listed scope.
func CoveringScopes(scopes ...Scope) ScopeSet {
	var bits uint32
	for _, scope := range scopes {
		bits |= scopeBit(scope, AccessRead) | scopeBit(scope, AccessWrite)
	}
	return ScopeSet{bits: bits}
}

// Bits is the raw wire form.
func (s ScopeSet) Bits() uint32 { return s.bits }

// With returns s plus (scope, access).
func (s ScopeSet) With(scope Scope, access Access) ScopeSet {
	return ScopeSet{bits: s.bits | scopeBit(scope, access)}
}

// Union returns s ∪ other.
func (s ScopeSet) Union(other ScopeSet) ScopeSet {
	return ScopeSet{bits: s.bits | other.bits}
}

// Contains reports whether (scope, access) is granted.
func (s ScopeSet) Contains(scope Scope, access Access) bool {
	return s.bits&scopeBit(scope, access) != 0
}

// IsSuperset reports whether every grant in other is also in s (s ⊇ other).
// Read bits count: a set is not a superset of one it can only write.
func (s ScopeSet) IsSuperset(other ScopeSet) bool {
	return s.bits&other.bits == other.bits
}

// IsSubset reports whether every grant in s is also in other (s ⊆ other).
func (s ScopeSet) IsSubset(other ScopeSet) bool { return other.IsSuperset(s) }

// IsEmpty reports whether the set grants nothing.
func (s ScopeSet) IsEmpty() bool { return s.bits == 0 }

// IsValid reports whether every set bit names a defined (scope, access).
func (s ScopeSet) IsValid() bool { return s.bits&^AllScopeSet().bits == 0 }

// String renders "deployments:rw, secrets:r" in index order; "(none)" when empty.
func (s ScopeSet) String() string {
	if s.IsEmpty() {
		return emptyScopeText
	}
	parts := make([]string, 0, len(scopeNames))
	for index, name := range scopeNames {
		scope := Scope(index)
		r := s.Contains(scope, AccessRead)
		w := s.Contains(scope, AccessWrite)
		if !r && !w {
			continue
		}
		access := ""
		if r {
			access += "r"
		}
		if w {
			access += "w"
		}
		parts = append(parts, name+":"+access)
	}
	return strings.Join(parts, ", ")
}

// ParseScopeSet parses "deployments:rw, secrets:r".
//
// Case-insensitive; entries may be separated by commas, whitespace, or both. An
// empty string and "(none)" both yield an empty set, so String round-trips.
func ParseScopeSet(text string) (ScopeSet, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || strings.EqualFold(trimmed, emptyScopeText) {
		return ScopeSet{}, nil
	}

	set := ScopeSet{}
	for _, entry := range strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		name, access, found := strings.Cut(entry, ":")
		if !found {
			return ScopeSet{}, fmt.Errorf(
				"scope entry %q is missing its :r, :w or :rw suffix", entry)
		}
		name = strings.ToLower(name)
		scope, ok := scopeByName(name)
		if !ok {
			return ScopeSet{}, fmt.Errorf("unknown scope %q", name)
		}

		var read, write bool
		for _, c := range strings.ToLower(access) {
			// A repeated letter means the caller's generator is confused;
			// folding it silently would hide that.
			switch {
			case c == 'r' && !read:
				read = true
			case c == 'w' && !write:
				write = true
			default:
				return ScopeSet{}, fmt.Errorf(
					"scope %q has invalid access %q: expected r, w, or rw", name, access)
			}
		}
		if !read && !write {
			return ScopeSet{}, fmt.Errorf(
				"scope %q has invalid access %q: expected r, w, or rw", name, access)
		}
		if read {
			set = set.With(scope, AccessRead)
		}
		if write {
			set = set.With(scope, AccessWrite)
		}
	}
	return set, nil
}

func scopeByName(name string) (Scope, bool) {
	for index, candidate := range scopeNames {
		if candidate == name {
			return Scope(index), true
		}
	}
	return 0, false
}

func writeScope(scope Scope) ScopeSet { return SingleScope(scope, AccessWrite) }

// deployWithSecret: shipping a secret into a container the key controls is a read
// of that secret.
var deployWithSecret = writeScope(ScopeDeployments).With(ScopeSecrets, AccessRead)

// report_consumption, report_capacity, request_consumption_report are
// provider-signed; the SKU and stake setters are root.
var resourcesWrite = map[string]bool{
	"register_resource":         true,
	"register_private_resource": true,
	"register_org_resource":     true,
	"reactivate_resource":       true,
	"set_resource_privacy":      true,
	"add_to_whitelist":          true,
	"remove_from_whitelist":     true,
	"update_resource_name":      true,
	"remove_resource":           true,
}

// create_org / delete_org stay human-signed.
var organizationWrite = map[string]bool{
	"add_member":                  true,
	"set_member_role":             true,
	"remove_member":               true,
	"create_project":              true,
	"assign_to_project":           true,
	"unassign_from_project":       true,
	"delete_project":              true,
	"add_project_deployment_peer": true,
}

// Everything else in budgets — the roster calls, so a key never mints authority,
// and the treasury value movers.
var billingWrite = map[string]bool{
	"allot":                   true,
	"defund_project":          true,
	"set_plan_allotment":      true,
	"add_purchased_allotment": true,
	"set_purchased_allotment": true,
	"set_member_billing":      true,
	"clear_member_billing":    true,
	"set_member_gas_limit":    true,
}

var deploymentsWrite = map[string]bool{
	"cancel_deployment":     true,
	"set_deployment_env":    true,
	"set_deployment_image":  true,
	"set_deployment_launch": true,
	"set_deployment_policy_root": true,
}

// RequiredScopes reports what pallet.call requires of a delegated key, and
// whether any set admits it at all. A false second return means no key may ever
// make the call — provider-signed, root-only, org lifecycle, the roster calls,
// and every treasury value mover.
//
// # This check is a courtesy, not a boundary
//
// The runtime's own filter is the only real enforcer. This exists so a caller
// reads "your key lacks volumes:w" instead of the pool rejection a balance-less
// delegated key actually gets, which complains about fees and names neither the
// call nor the scope. It follows that being wrong in the *safe* direction —
// demanding more than the chain would — costs a caller a local rejection they can
// work around, while the opposite would let through a call the chain then
// refuses. So where an argument cannot be read, the wider set is required.
//
// Because Go submits a pre-built types.Call, the argument-sensitive rows cannot
// inspect arguments here; requiredScopesForCall does that from the encoded call.
func RequiredScopes(pallet, call string) (ScopeSet, bool) {
	switch pallet {
	case "Jobs":
		switch {
		case call == "request_deployment" || call == "set_deployment_secret_ref":
			// Argument-dependent; the wider set is the safe answer by name alone.
			return deployWithSecret, true
		case deploymentsWrite[call]:
			return writeScope(ScopeDeployments), true
		case call == "register_wg_peer" || call == "remove_wg_peer":
			return writeScope(ScopeNetworking), true
		default:
			// update_deployment_status, set_deployment_network,
			// report_tls_status: provider-signed.
			return ScopeSet{}, false
		}
	case "Collaborations":
		// Every call but the two root-only setters, cranks included.
		if call == "set_compute_node_image" || call == "set_compute_node_sku_id" {
			return ScopeSet{}, false
		}
		return writeScope(ScopeCollaborations), true
	case "Secrets":
		return writeScope(ScopeSecrets), true
	case "Volumes":
		return writeScope(ScopeVolumes), true
	case "OverlayNetworks":
		return writeScope(ScopeNetworking), true
	case "Datasets":
		if strings.HasPrefix(call, "force_") {
			return ScopeSet{}, false
		}
		return writeScope(ScopeDatasets), true
	case "Communities":
		if strings.HasPrefix(call, "force_") {
			return ScopeSet{}, false
		}
		return writeScope(ScopeCommunities), true
	case "Resources":
		if resourcesWrite[call] {
			return writeScope(ScopeResources), true
		}
		return ScopeSet{}, false
	case "Organizations":
		if organizationWrite[call] {
			return writeScope(ScopeOrganization), true
		}
		return ScopeSet{}, false
	case "Budgets":
		if billingWrite[call] {
			return writeScope(ScopeBilling), true
		}
		return ScopeSet{}, false
	default:
		return ScopeSet{}, false
	}
}

// requiredScopesForCall is RequiredScopes with the two argument-sensitive rows
// resolved from the encoded call.
//
// The chain reads those arguments, so judging by name alone refuses calls the
// runtime would have admitted: clearing a deployment's secret ref needs no
// Secrets scope at all. Anything this cannot read — a missing registry, a field
// that will not decode, a shape it does not recognise — takes the wider set,
// because a false refusal is a message the caller can act on and a false
// admission is a rejected extrinsic they cannot.
func requiredScopesForCall(meta *types.Metadata, calls registry.CallRegistry, call types.Call) (ScopeSet, bool) {
	pallet, method, ok := callNames(meta, call.CallIndex)
	if !ok {
		return EmptyScopeSet(), false
	}
	required, admitted := RequiredScopes(pallet, method)
	if !admitted || pallet != "Jobs" {
		return required, admitted
	}

	// Only the two Jobs rows depend on an argument, and each is narrower exactly
	// when its secret reference is absent.
	var field string
	switch method {
	case "set_deployment_secret_ref":
		field = "secret_ref"
	case "request_deployment":
		field = "request"
	default:
		return required, admitted
	}

	fields, err := decodeCallFields(calls, call)
	if err != nil {
		return required, admitted
	}
	if referencesNoSecret(fields, field) {
		return writeScope(ScopeDeployments), true
	}
	return required, admitted
}

// decodeCallFields decodes a call's arguments using the metadata's own decoders.
func decodeCallFields(calls registry.CallRegistry, call types.Call) (registry.DecodedFields, error) {
	if calls == nil {
		return nil, fmt.Errorf("no call registry")
	}
	decoder, ok := calls[call.CallIndex]
	if !ok {
		return nil, fmt.Errorf("no decoder for call %d.%d",
			call.CallIndex.SectionIndex, call.CallIndex.MethodIndex)
	}
	return decoder.Decode(scale.NewDecoder(bytes.NewReader(call.Args)))
}

// referencesNoSecret reports whether `field` is present and decodes to
// Option::None — for request_deployment, whether neither secret reference in the
// request struct is set.
//
// GSRPC's registry discards variant names, so a no-field arm arrives as its bare
// variant byte: Option::None is byte 0 and Some carries its inner value. Only an
// exact byte 0 is read as absent; every other shape falls through to the wider
// set rather than being guessed at.
func referencesNoSecret(fields registry.DecodedFields, field string) bool {
	for _, f := range fields {
		if f == nil || !fieldNamed(f.Name, field) {
			continue
		}
		if field != "request" {
			return isOptionNone(f.Value)
		}
		// request_deployment carries both references inside its request struct.
		inner, ok := f.Value.(registry.DecodedFields)
		if !ok {
			return false
		}
		var sawSecret, sawTLS bool
		for _, ref := range inner {
			if ref == nil {
				continue
			}
			switch {
			// tls_secret_ref first: it also ends in "secret_ref".
			case fieldNamed(ref.Name, "tls_secret_ref"):
				sawTLS = true
				if !isOptionNone(ref.Value) {
					return false
				}
			case fieldNamed(ref.Name, "secret_ref"):
				sawSecret = true
				if !isOptionNone(ref.Value) {
					return false
				}
			}
		}
		// Both must have been seen and both absent; a request whose shape changed
		// under us is not evidence that no secret is referenced.
		return sawSecret && sawTLS
	}
	return false
}

// fieldNamed matches a metadata field name, which the registry prefixes with the
// name of the type that declared it ("Option.secret_ref" for a secret_ref field
// of type Option<u128>).
func fieldNamed(actual, want string) bool {
	return actual == want || strings.HasSuffix(actual, "."+want)
}

func isOptionNone(value any) bool {
	b, ok := value.(byte)
	return ok && b == 0
}
