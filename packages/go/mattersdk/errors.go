package mattersdk

// Error kinds match TypeScript's ClientErrorKind and Rust's SdkError; see
// docs/parity.md.

import "fmt"

// ChainErrorKind names a failure a caller may reasonably branch on.
type ChainErrorKind string

const (
	// KindReadOnly is a submission attempted by a client that holds no signer.
	KindReadOnly ChainErrorKind = "read-only"
	// KindConfig is a connection configuration that is inconsistent or incomplete.
	KindConfig ChainErrorKind = "config"
	// KindWrongNetwork is an endpoint serving a different network than the config
	// selected.
	KindWrongNetwork ChainErrorKind = "wrong-network"
	// KindMainnetNotConfirmed is a signing client pointed at mainnet without
	// explicit confirmation.
	KindMainnetNotConfirmed ChainErrorKind = "mainnet-not-confirmed"
	// KindChain is a chain interaction that failed for a reason with no more
	// specific kind: a dropped connection, an unresolvable name, a bad response.
	KindChain ChainErrorKind = "chain"
	// KindNotPermitted is a call this key's scopes do not cover.
	KindNotPermitted ChainErrorKind = "not-permitted"
	// KindNeverAdmitted is a call no scoped key may ever make, whatever its scopes.
	KindNeverAdmitted ChainErrorKind = "never-admitted"
	// KindDispatch is a wrapped call that the runtime refused after the outer
	// proxy.proxy extrinsic had already succeeded.
	KindDispatch ChainErrorKind = "dispatch"
	// KindKeyRevoked is a key whose proxy is gone or rebound since connect.
	KindKeyRevoked ChainErrorKind = "key-revoked"
	// KindUnsponsored is a call the key may make but that nobody will pay for.
	KindUnsponsored ChainErrorKind = "unsponsored"
	// KindFinalityTimeout is a submission that was not finalized in time. The
	// extrinsic may still land, so this is never a licence to resubmit blindly.
	KindFinalityTimeout ChainErrorKind = "finality-timeout"
)

// ChainError is a typed chain failure. Branch on Kind with errors.As, never on
// the message text.
type ChainError struct {
	Kind ChainErrorKind
	// Target is the "Pallet.call" this concerns, where there is one.
	Target string
	Msg    string
	// Err is the underlying cause, kept so errors.Is still reaches it.
	Err error
}

func (e *ChainError) Error() string { return e.Msg }

func (e *ChainError) Unwrap() error { return e.Err }

func chainErrorf(kind ChainErrorKind, target string, format string, args ...any) *ChainError {
	return &ChainError{Kind: kind, Target: target, Msg: fmt.Sprintf(format, args...)}
}

// wrapChainError keeps cause reachable through errors.Is while giving the
// failure a kind.
func wrapChainError(kind ChainErrorKind, target string, cause error, format string, args ...any) *ChainError {
	return &ChainError{Kind: kind, Target: target, Msg: fmt.Sprintf(format, args...), Err: cause}
}
