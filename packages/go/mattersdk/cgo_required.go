//go:build !cgo

package mattersdk

// Without cgo, files importing "C" are excluded and the build fails with unexplained
// "undefined: ApiKey" errors. Go reports type declarations first, in file-name order,
// and stops after ten errors, so the `type` form and this file's name keep this
// sentinel the first error. scripts/smoke-go-module.sh checks it.
type _ mattersdk_requires_cgo__build_with_CGO_ENABLED_1_and_a_C_compiler
