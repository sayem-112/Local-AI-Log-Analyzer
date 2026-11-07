#!/usr/bin/env sh
# Start the local model server (Linux/macOS). Flag reasons: see scripts/start_model.ps1.
# Usage: scripts/start_model.sh [models/Qwen3.5-2B-Q4_K_M.gguf] [8081]
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${1:-models/Qwen3.5-2B-Q4_K_M.gguf}"
PORT="${2:-8081}"
exec "${LLAMA_SERVER:-$ROOT/bin/llama/llama-server}" -m "$ROOT/$MODEL" -c 2048 -t 2 -tb 2 -np 1 \
  --reasoning off --no-mmproj --cache-ram 0 --ctx-checkpoints 8 --host 127.0.0.1 --port "$PORT"
