# test/

All of this repository's Go tests live here rather than beside the code they
test. That is not the Go default, so this file explains why, and what the move
cost, so the next person does not undo it.

## Why the tests are not in the package directories

Go ties a test file to the package it tests. The internal form (`package edge`)
reaches only into its own directory. The external form (`package edge_test`)
still has to sit in that directory to find the package it is testing. There is no
import path that makes an unexported identifier visible from elsewhere.

So a test that exercises internal state has to be in the package directory. The
tests here were moved out anyway, which is only possible by exporting what they
touch -- see below.

There is also a mechanical reason for the subdirectories. A Go package is one
directory with one package name, so tests from five different packages cannot sit
in a single flat `test/`. Hence `test/edge/`, `test/p2p/`, and so on.

## What each directory is

| Directory | Tests |
|---|---|
| `test/edge/` | `pkg/edge` (19 files) |
| `test/p2p/` | `pkg/p2p` (18 files) |
| `test/transport/` | `pkg/transport` |
| `test/natclient/` | `pkg/natclient` |
| `test/codec/` | `pkg/protocol/codec` |

141 test functions in 40 files. Run them all with:

    go test ./test/...

## How the files are wired

Each file is now `package <name>_test` with a dot-import of the package under
test:

    package edge_test

    import . "n2n-go/pkg/edge"

The dot-import is what kept the move mechanical. Test bodies call the symbols they
exercise unqualified, and qualifying every one of them would have been a large
diff in files whose contents did not otherwise change. Files that end up
referring to nothing from the package have the import removed -- the compiler
reports those as unused, which is more reliable than any static guess.

## The hooks this required

An external package cannot see unexported identifiers *or* unexported fields, so
the move forced a choice for everything the tests reach. There are two kinds.

**Test hooks** -- methods added to production types, each carrying a comment that
says it exists for `test/` and is not supported API:

- `PeerRegistry`: `LockForTest`, `UnlockForTest`, `NatHoleInstructionsForTest`,
  `SetNatHoleInstructionsForTest`, `GraceUnlistedCountForTest`,
  `ExpireGraceTombstonesForTest`, `RecordNatHolePunchResultForTest`,
  `NatHolePunchResultsForTest`, `NatHoleRetryCountsForTest`,
  `SetNatHoleRetryCountsForTest`, `SetPeerBySocketForTest`, `LastNatHoleInstrs`
- `Peer`: `LookupSockets`
- `RawRecvLogger`: `NewRawRecvLoggerForTest`
- `STUNClient`: `PendingTransactionForTest`

**Exported identifiers** -- previously unexported functions, constants and types,
renamed so the tests can name them. Behaviour is unchanged; only the spelling is.
All of them already had doc comments, so the Godoc reads correctly after the
rename. These cover the local-address ranking helpers, the punch-target and NAT
classification helpers, the affinity helpers in `pkg/p2p`, the IPv4/IPv6 ordering
helpers in `pkg/transport`, and `PendingProbe`.

## Two things this improved rather than merely permitted

`rawRecvLogger` gained an injectable clock (`now func()`, nil meaning real time,
via `NewRawRecvLoggerForTest`). Two tests used to reach into `l.mu` and
`l.shapes` to backdate a source; they now advance a fake clock instead. The
zero value still works, so the production instance needed no change.

`rawRecvLogger`'s re-log and eviction timing is no longer coupled to wall time in
tests, which also removes the sleep the old eviction test implied.

## Cost worth knowing about

Forty-three identifiers now exist only so these tests can reach them: the
thirteen hooks above, plus thirty formerly unexported functions, constants and
types renamed to start with a capital (`CollectAssistedIPs`, `IsPublicRoutable`,
`OrderByFamily`, `RankReceiverCandidates`, `TapAddressSpace`, and so on). They
are documented as unsupported, but nothing stops a caller from using them, and
the compiler will not flag that misuse.

If a future change makes a package awkward to keep in this layout, moving that
package's tests back beside the code is cheaper than continuing to widen the
API. The tests are the only consumers, and the conversion is one scripted pass
over one directory.

One test, `TestHandleNatHoleInstructionCopiesEveryField`, reads `pkg/edge`'s
source to compare a struct literal against the proto. It resolves the path
through `runtime.Caller` rather than a relative path, because its working
directory is no longer the directory it reads from.
