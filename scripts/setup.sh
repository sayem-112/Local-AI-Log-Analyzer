#!/usr/bin/env sh
# One-time setup (Linux x64). Needs internet; everything after this runs offline.
#   scripts/setup.sh          # 2B model (default)
#   SMALL=1 scripts/setup.sh  # also fetch the 0.8B model
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD=b12182  # pinned llama.cpp release that was tested

python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install -q -r "$ROOT/requirements.txt"

if [ ! -x "$ROOT/bin/llama/llama-server" ]; then
  mkdir -p "$ROOT/bin/llama"
  curl -fsSL "https://github.com/ggml-org/llama.cpp/releases/download/$BUILD/llama-$BUILD-bin-ubuntu-x64.tar.gz" \
    | tar -xz -C "$ROOT/bin/llama" --strip-components=1
fi

mkdir -p "$ROOT/models"
fetch() { [ -f "$ROOT/models/$2" ] || curl -fL -o "$ROOT/models/$2" "https://huggingface.co/$1/resolve/main/$2"; }
fetch unsloth/Qwen3.5-2B-GGUF Qwen3.5-2B-Q4_K_M.gguf
[ -n "$SMALL" ] && fetch unsloth/Qwen3.5-0.8B-GGUF Qwen3.5-0.8B-Q4_K_M.gguf
echo "Setup done. Start the model: scripts/start_model.sh   Then the app: .venv/bin/uvicorn app.main:app --port 8000"
