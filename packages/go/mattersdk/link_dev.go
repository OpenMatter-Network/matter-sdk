package mattersdk

// Where cgo finds the Rust core when this package is built INSIDE the matter-sdk
// monorepo. The published module (github.com/openmatter-network/matter-sdk-go) does not
// contain this file: scripts/assemble-go-module.sh leaves it out and generates a link.go
// that names the prebuilt archives shipped beside the sources instead.
//
// Build the archive first, from the repo root:
//
//	cargo build -p matter-sdk-ffi --release
//
// The archive is named by path, not found with -L/-l. target/release holds both
// libmatter_sdk_ffi.a and .so, and -lmatter_sdk_ffi picks the shared object — after
// which every binary, `go test` included, needs LD_LIBRARY_PATH to start. The system
// libraries are the ones `rustc --print native-static-libs` names for the archive.

/*
#cgo CFLAGS: -I${SRCDIR}/../../../crates/matter-sdk-ffi/include
#cgo LDFLAGS: ${SRCDIR}/../../../target/release/libmatter_sdk_ffi.a -lm
#cgo linux LDFLAGS: -lrt -lpthread -lutil -ldl
#cgo darwin LDFLAGS: -liconv
*/
import "C"
