package main

// sentinelTestPadding is a linker-padding target for scripts/gotest.ps1.
//
// The Windows Application Control rule on this dev host blocks freshly linked test
// binaries by content hash. Rotating `-ldflags -buildid=` is not always enough,
// because the package set is fixed and a 5-bit build-id space occasionally lands
// on hashes the policy also rejects. `-X sentinelTestPadding=...` adds more entropy
// to the linked bytes.
//
// Declared in a _test.go file deliberately: the go tool links a package's test
// files into its test binary, so the symbol is present where it is needed, and
// the production package stays free of a variable that exists only to be
// hashed. That distinction is the point - cruft added to working code for a
// developer-machine problem is cruft forever.
//
// Never read. Its only job is to occupy bytes.
var sentinelTestPadding = "unset"
