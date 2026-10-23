#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Compiling Protobuf schemas..."

export PATH="${PATH}:$(go env GOPATH)/bin"

protoc --proto_path="${ROOT_DIR}/api/proto/v1" \
  --go_out="${ROOT_DIR}/api/proto/v1" --go_opt=paths=source_relative \
  --go-grpc_out="${ROOT_DIR}/api/proto/v1" --go-grpc_opt=paths=source_relative \
  "${ROOT_DIR}/api/proto/v1/alinksec_hub.proto"

echo "==> Protobuf code generation completed successfully."
