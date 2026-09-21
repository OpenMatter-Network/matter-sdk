//go:build !cgo

package mattersdk

// Without cgo every file that imports "C" is silently excluded, and the build fails with
// a page of "undefined: ApiKey"-style errors about this package's own symbols — none of
// which says why. Go stops after ten errors, so the explanation has to be the FIRST one:
// the type checker reports type declarations before anything else, in file-name order.
// Both the `type` form and this file's name are therefore load-bearing;
// scripts/smoke-go-module.sh fails if the sentinel stops being reported.
type _ mattersdk_requires_cgo__build_with_CGO_ENABLED_1_and_a_C_compiler
