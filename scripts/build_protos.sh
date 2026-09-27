#!/bin/bash
# Regenerate pkg/p2p/p2p.pb.go from pkg/p2p/proto/p2p.proto.
#
# The .proto is the single source of truth for the wire schema: edit it, run
# this, and commit both. The generated file must never be hand-edited.
#
# go_package is "n2n-go/pkg/p2p", so the output has to be placed at
# pkg/p2p/p2p.pb.go, NOT next to the .proto. --go_opt=module=n2n-go strips the
# module prefix, while --go_opt=paths=source_relative would drop the file at
# pkg/p2p/proto/p2p.pb.go and leave the real one stale -- a mismatch that
# silently produces a second, divergent copy of the schema.
set -euo pipefail
cd "$(dirname "$0")/.."

PROTO=pkg/p2p/proto/p2p.proto
OUT_TMP=$(mktemp -d /tmp/pbgen.XXXXXX)
trap 'rm -rf "$OUT_TMP"' EXIT

if [ -x /root/go/bin/protoc-gen-go ]; then
    export PATH="$PATH:/root/go/bin"
fi
if [ -x /usr/local/go/bin ]; then
    export PATH="$PATH:/usr/local/go/bin"
fi

command -v protoc >/dev/null || { echo "protoc not found" >&2; exit 1; }
command -v protoc-gen-go >/dev/null || {
    echo "protoc-gen-go not found: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" >&2
    exit 1
}

protoc --go_out="$OUT_TMP" --go_opt=module=n2n-go -I . "$PROTO"

GENERATED="$OUT_TMP/pkg/p2p/p2p.pb.go"
[ -f "$GENERATED" ] || { echo "unexpected protoc output layout:" >&2; find "$OUT_TMP" -name '*.pb.go' >&2; exit 1; }

cp "$GENERATED" pkg/p2p/p2p.pb.go
echo "regenerated pkg/p2p/p2p.pb.go"
