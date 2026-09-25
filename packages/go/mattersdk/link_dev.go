package mattersdk

// cgo link flags for in-monorepo builds. The published module omits this file;
// scripts/assemble-go-module.sh generates a link.go for the prebuilt archives instead.
//
// Build the archive first, from the repo root:
//
//	cargo build -p matter-sdk-ffi --release
//
// The archive is linked by path because -lmatter_sdk_ffi would pick the .so and
// require LD_LIBRARY_PATH. System libraries come from `rustc --print native-static-libs`.

/*
#cgo CFLAGS: -I${SRCDIR}/../../../crates/matter-sdk-ffi/include
#cgo LDFLAGS: ${SRCDIR}/../../../target/release/libmatter_sdk_ffi.a -lm
#cgo linux LDFLAGS: -lrt -lpthread -lutil -ldl
#cgo darwin LDFLAGS: -liconv
*/
import "C"
